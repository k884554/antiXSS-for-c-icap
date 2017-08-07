#include <string.h>
#include <stdlib.h>
#include "common.h"
#include <c_icap/c-icap.h>
#include <c_icap/service.h>
#include <c_icap/header.h>
#include <c_icap/body.h>
#include <c_icap/simple_api.h>
#include <c_icap/debug.h>
#include<pcre.h>

int echo_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf);
int echo_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t *);
int echo_end_of_data_handler(ci_request_t * req);
void *echo_init_request_data(ci_request_t * req);
void echo_close_service();
void echo_release_request_data(void *data);
int echo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,ci_request_t * req);

pcre * pcreCompile(const char *);
int pcreMatch(pcre *,const char *);

static const char mod_security1[]="(@pm|jscript|onsubmit|copyparentfolder|javascript|meta|onmove|onkeydown|onchange|onkeyup|activexobject|expression|onmouseup|ecmascript|onmouseover|vbscript\\:|(%%3C)!\\[cdata\\[|http\\:|settimeout|onabort|shell\\:|\\.innerhtml|onmousedown|onkeypress|asfunction\\:|onclick|\\.fromcharcode|background-image\\:|\\.cookie|ondragdrop|onblur|x-javascript|mocha:|onfocus|javascript:|getparentfolder|lowsrc|onresize|@import|alert|onselect|script|onmouseout|onmousemove|background|application|\\.execscript|livescript:|getspecialfolder|vbscript|iframe|\\.addimport|onunload|createtextrange|onload|(%%3C)input)";

static const char mod_security2[]="(?:\\b(?:(?:type\\b\\W*?\\b(?:text\\b\\W*?\\b(?:j(?:ava)?|ecma|vb)|application\\b\\W*?\\bx-(?:java|vb))script|c(?:opyparentfolder|reatetextrange)|get(?:special|parent)folder|iframe\\b.{0,100}?\\bsrc)\\b|on(?:(?:mo(?:use(?:o(?:ver|ut)|down|move|up)|ve)|key(?:press|down|up)|c(?:hange|lick)|s(?:elec|ubmi)t|(?:un)?load|dragdrop|resize|focus|blur)\\b\\W*?=|abort\\b)|(?:l(?:owsrc\\b\\W*?\\b(?:(?:java|vb)script|shell|http)|ivescript)|(?:href|url)\\b\\W*?\\b(?:(?:java|vb)script|shell)|background-image|mocha):|s(?:(?:tyle\\b\\W*=.*\\bexpression\\b\\W*|ettimeout\\b\\W*?)\\(|rc\\b\\W*?\\b(?:(?:java|vb)script|shell|http):)|a(?:ctivexobject\\b|lert\\b\\W*?\\(|sfunction:))|(%3C)(?:(?:body\\b.*?\\b(?:backgroun|onloa)d|input\\b.*?\\btype\\b\\W*?\\bimage)\\b| ?(?:(?:script|meta)\\b|iframe)|!\\[cdata\\[)|(?:\\.(?:(?:execscrip|addimpor)t|(?:fromcharcod|cooki)e|innerhtml)|\\@import)\\b)";

static pcre * ms1;
static pcre * ms2;

void redirectURL(ci_request_t * req, const char * url);
int apache_mod_security(const char * str);

static const char * denied = "http://localhost/a.php";

CI_DECLARE_MOD_DATA ci_service_module_t service = {
    "echo",
    "Echo demo service",
    ICAP_RESPMOD | ICAP_REQMOD,
    echo_init_service,
    NULL,
    echo_close_service,
    echo_init_request_data,
    echo_release_request_data,
    echo_check_preview_handler,
    echo_end_of_data_handler,
    echo_io,
    NULL,
    NULL
};

struct echo_req_data {
    ci_ring_buf_t *body;
    int eof;
};


int echo_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf)
{
    ci_debug_printf(0, "Initialization of echo module......\n");

    ci_service_set_preview(srv_xdata, 1024);

    ci_service_enable_204(srv_xdata);

    ci_service_set_transfer_preview(srv_xdata, "*");

    ci_service_set_xopts(srv_xdata,  CI_XAUTHENTICATEDUSER|CI_XAUTHENTICATEDGROUPS);
    
    ms1=pcreCompile(mod_security1);
    ms2=pcreCompile(mod_security2);

    return CI_OK;
}

void echo_close_service()
{
    ci_debug_printf(0,"Service shutdown!\n");
    free(ms1);
    free(ms2);
}

void *echo_init_request_data(ci_request_t * req)
{
    struct echo_req_data *echo_data;

    echo_data = malloc(sizeof(struct echo_req_data));
    if (!echo_data) {
        ci_debug_printf(0, "Memory allocation failed inside echo_init_request_data!\n");
        return NULL;
    }

    if (ci_req_hasbody(req))
        echo_data->body = ci_ring_buf_new(4096);
    else
        echo_data->body = NULL;

    echo_data->eof = 0;
    return echo_data;
}

void echo_release_request_data(void *data)
{

    struct echo_req_data *echo_data = (struct echo_req_data *)data;

    if (echo_data->body)
        ci_ring_buf_destroy(echo_data->body);

    free(echo_data);
}


static int whattodo = 0;
int echo_check_preview_handler(char *preview_data, int preview_data_len,ci_request_t * req)
{
    struct echo_req_data *echo_data = ci_service_data(req);
    const char *url = ci_http_request(req);
    
    if(url){
        ci_debug_printf(0,"[*]REQMOD: The Request is %s\n", url);
        if(apache_mod_security(url)){
            redirectURL(req,denied);
        }
    }
    
    ci_debug_printf(0,"[*]REQMOD: [Preview] Checked HTTP Header\n");

    if(!ci_req_hasbody(req)){
        ci_debug_printf(0,"[*]REQMOD: [Preview] NO HTTP BODY. \n");
    }else{
        ci_debug_printf(0,"[*]REQMOD: [Preview] There are HTTP BODY! AHA :D\n");
    }
    
    if (!preview_data_len){
        ci_debug_printf(0,"[*]REQMOD: [Preview] Preview hasnt a body but only headers \n");
    }
    
    if(preview_data_len){
        if(apache_mod_security(preview_data))redirectURL(req,denied);
        ci_debug_printf(0,"[*]REQMOD: [Preview] MOD_CONTINUE\n");
        ci_ring_buf_write(echo_data->body, preview_data, preview_data_len);
        echo_data->eof = ci_req_hasalldata(req);
    }
    
    return CI_MOD_CONTINUE;
}

int echo_end_of_data_handler(ci_request_t * req)
{
    struct echo_req_data *echo_data = ci_service_data(req);
    echo_data->eof = 1;
    return CI_MOD_DONE;
}

int echo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t * req)
{
    int ret;
    struct echo_req_data *echo_data = ci_service_data(req);
    ret = CI_OK;

    if (rlen && rbuf) {
        *rlen = ci_ring_buf_write(echo_data->body, rbuf, *rlen);
        if (*rlen < 0)
            ret = CI_ERROR;
    }

    if (wbuf && wlen) {
        *wlen = ci_ring_buf_read(echo_data->body, wbuf, *wlen);
    }
    if (*wlen==0 && echo_data->eof==1)
        *wlen = CI_EOF;

    return ret;
}

pcre * pcreCompile(const char * reg){
    int error_basyo;
    const char * err_msg;
    pcre * reg_p = pcre_compile(reg,PCRE_CASELESS,&err_msg,&error_basyo,NULL);
    if(reg_p == NULL){
        ci_debug_printf(0,"[*]REQMOD: Error in pcrCompile! %s in %dth Byte\n",err_msg,error_basyo);
        return NULL;
    }
    return reg_p;
}

int pcreMatch(pcre * reg_p,const char * txt){
    int maxMatch= sizeof(char) * 33 * 3;
    int matched_basyo[maxMatch];
    int howManyMatched = pcre_exec(reg_p,NULL,txt,strlen(txt),0,0,matched_basyo,maxMatch);
    return howManyMatched;
}

void redirectURL(ci_request_t * req, const char * url){
    ci_http_request_reset_headers(req);
    int gh = strlen("GET HTTP/1.0");
    int urllen = strlen(url);
    char header1[gh + urllen];
    snprintf(header1,(gh + urllen + 2),"GET %s HTTP/1.0",url);
    ci_http_request_add_header(req,header1);
    ci_http_request_add_header(req,"Accept: */*;q=0.1");
    ci_debug_printf(0,"[*]REQMOD:URL <= %s\n",ci_http_request(req));
}

int apache_mod_security(const char * str){
    if(pcreMatch(ms1,str) > 0){
        ci_debug_printf(0,"[*]REQMOD: [modSecurity] Step1 -- deny\n");
        if(pcreMatch(ms2,str) > 0){
            ci_debug_printf(0,"[*]REQMOD: [modSecurity] Step2 -- deny\n");
            return 1;
        }
    }
    return 0;
}
