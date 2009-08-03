/*
 * Copyright 2008-2009 Michael Koziarski and Pratik Naik
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apr_sha1.h>
#include <apreq_util.h>
#include <apreq2/apreq_module_apache2.h>

#define HTTP_X_UPLOADS "X-Uploads"

#ifdef PORTER_DEBUG
  #define PORTER_LOG(expr) fprintf(stderr, "[PORTER_LOG] %s\n", expr) && fflush(stderr)
#else
  #define PORTER_LOG(expr)
#endif

#define PORTER_LOG_REQUEST_ERROR(error) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, error)

#define PORTER_HANDLE_ERROR(expr) \
  rv = expr;                  \
  if (rv != APR_SUCCESS)      \
  {                           \
    return rv;                \
  }



AP_DECLARE_DATA ap_filter_rec_t *porter_input_filter_handle;

typedef struct porter_upload_request_t {
  apreq_handle_t *request;
  apr_array_header_t *param_names;
  apr_bucket_brigade *bucket_brigade;
  apr_status_t status;
  apr_pool_t *pool;
  request_rec *raw_request;
  const char *secret;
} porter_upload_request_t;

typedef struct porter_server_conf {
  int enabled;
  apr_uint64_t minimum_multipart_size;
  const char *secret;
  apr_fileperms_t permission;
} porter_server_conf;

extern module AP_MODULE_DECLARE_DATA porter_module;

int porter_should_rewrite_body(request_rec *r, porter_server_conf *config);
apr_status_t porter_process_upload(request_rec *r);
int porter_each_parameter(void *data, const char *key, const char *val);
apr_status_t porter_handle_parameter(porter_upload_request_t *ur, apreq_param_t *param);
apr_status_t porter_handle_parameter(porter_upload_request_t *ur, apreq_param_t *param);
apr_status_t porter_handle_upload(porter_upload_request_t *ur, apreq_param_t *p);
char *porter_sign_filename(porter_upload_request_t *ur, apr_finfo_t *finfo);
apr_status_t porter_stream_file_to_disk(apr_pool_t *pool, apreq_param_t *p, apr_finfo_t *finfo);
apr_status_t porter_append_sub_parameter(apr_pool_t *pool, apr_bucket_brigade *bb,
                                     const char *parent_param,
                                     const char *sub_param,
                                     const char *sub_param_value,
                                     apr_size_t length);
porter_upload_request_t* porter_create_request(apreq_handle_t *req,
                                      request_rec *raw_request,
                                      porter_server_conf *config);
                                     
// This input filter handles the job of rewriting the request, it's injected at
// runtime by the porter fixup filter.  All it does is remove itself from the
// filter chain and pass the newly modified content up the filter chain.
static apr_status_t porter_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                    ap_input_mode_t mode, apr_read_type_e block,
                                    apr_off_t readbytes)
{
  porter_upload_request_t *ur = f->ctx;

  if (!ur) {
    // Because we add ourselves dynamically, this should never occur.
    // but handle it anyway.
    return ap_get_brigade(f->next, bb, mode, block, readbytes);
  }

  // Remove ourselves so we don't trigger again.
  ap_remove_input_filter(f);

  APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc)) ;
  APR_BRIGADE_PREPEND(bb, ur->bucket_brigade);

  apr_brigade_destroy(ur->bucket_brigade);

  return APR_SUCCESS;
}

// The fixup filter's job is to determine if the content body needs to be rewritten,
// and if it does need to be rewritten, it triggers the work
static int porter_fixup(request_rec *r)
{
  apr_status_t rv;
  apr_table_setn(r->headers_in, HTTP_X_UPLOADS, NULL);

  porter_server_conf *config = (porter_server_conf *)ap_get_module_config(r->server->module_config, &porter_module);

  if(!config->enabled)
  {
    PORTER_LOG("Sadly you don't want your uploads to scale !! Good bye");
    return DECLINED;
  }

  int http_status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
  if (http_status != OK) {
    return http_status;
  }

  if (porter_should_rewrite_body(r, config))
  {
    PORTER_HANDLE_ERROR(porter_process_upload(r));
  }

  return DECLINED;
}


// Determines whether or not porter should apply.  Return true if the content
// type is multipart/form-data and the content length is greater than
// PorterMinSize.
int porter_should_rewrite_body(request_rec *r, porter_server_conf *config)
{
  if (ap_should_client_block(r))
  {
    const char *content_type   = apr_table_get(r->headers_in, "Content-Type");
    const char *content_length = apr_table_get(r->headers_in, "Content-Length");
    if (content_type && strcasecmp(content_type, "multipart/form-data") > 0 && atol(content_length) > config->minimum_multipart_size)
    {
      return 1;
    }
  }
  return 0;
}


// This is the method which does all the work handling the uploads.  It's only
// triggered by the fixup filter if +porter_should_rewrite_body+ returns true.
apr_status_t porter_process_upload(request_rec *r)
{
  porter_server_conf *config = (porter_server_conf *) ap_get_module_config(r->server->module_config, &porter_module);

  // Prepare the apreq objects.
  apreq_handle_t *req = apreq_handle_apache2(r);
  const apr_table_t *request_body = apreq_params(req, r->pool);

  // Create our upload request object, this is fleshed out by the rest of this method
  porter_upload_request_t *upload_request = porter_create_request(req, r, config);

  // This happens with malformed requests.  apreq_params should never return null
  // when the content-length is > 0 and it's a multipart request.  So just assume
  // it's broken and return bad request.  Otherwise subsequent method calls will
  // cause a segfault
  if (request_body == NULL)
  {
    PORTER_LOG_REQUEST_ERROR("Invalid request body");
    return HTTP_BAD_REQUEST;
  }

  // loop over each parameter provided by the user (see porter_each_parameter)
  apr_table_do(porter_each_parameter, upload_request, request_body, NULL);

  // If any of the parameter handlers return an error, they save the error code
  // in the upload_request.  So return that same error code.
  if (upload_request->status != APR_SUCCESS)
  {
    return upload_request->status;
  }


  // Just because the content type is multipart and the content-length was > 0 doesn't
  // mean that the user actually uploaded any files.  If they didn't, just return success
  // and let the original body be passed upstream.
  if (!apr_is_empty_array(upload_request->param_names))
  {
    // Write the parameter names to the X-Uploads header (comma seperated)
    const char *upload_parameters = apr_array_pstrcat(r->pool, upload_request->param_names, ',');
    apr_off_t len;
    apr_table_setn(r->headers_in, HTTP_X_UPLOADS, upload_parameters);

    // figure out the length of the newly rewritten body and set it in the request
    // along with the right content type.
    apr_brigade_length(upload_request->bucket_brigade, 0, &len);
    apr_table_setn(r->headers_in, "Content-Length", apr_itoa(r->pool, len));
    apr_table_setn(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");

    // Add our input filter to the filter chain, this allows
    // us to replace the request body with our own one, and ensure that
    // gets passed down to the handler.
    ap_add_input_filter_handle(porter_input_filter_handle, upload_request, r, r->connection);
  }
  return APR_SUCCESS;
}

// This is the iterator which handles every parameter and rewrites them as needed.
// If the parameter is an upload, it passes it to porter_handle_upload otherwise
// it calls porter_handle_parameter.
int porter_each_parameter(void *data, const char *key, const char *val)
{
  porter_upload_request_t *ur = (porter_upload_request_t*)data;
  apreq_param_t           *p  = apreq_value_to_param(val);
  apr_status_t             rv;

  if (p->upload == NULL) 
  {
    rv = porter_handle_parameter(ur, p);
  }
  else 
  {
    rv = porter_handle_upload(ur, p);
  }

  if (rv != APR_SUCCESS)
  {
    // save the error code and stop iterating, the filter will signal
    // the error.
    ur->status = rv;
    return 0;
  }
  return 1;
}



// Handles a simple parameter value, simply concats the name and value to the output 
// stream
apr_status_t porter_handle_parameter(porter_upload_request_t *ur, apreq_param_t *param)
{
  const char *new_parameter_value;
  apr_status_t rv;

  new_parameter_value = apr_pstrcat(ur->pool, apreq_escape(ur->pool, param->v.name, strlen(param->v.name)), "=",
                                              apreq_escape(ur->pool, param->v.data, strlen(param->v.data)), "&",
                                              NULL);
  PORTER_LOG("Writing plain parameter");
  PORTER_LOG(param->v.name);
  PORTER_LOG(new_parameter_value);

  PORTER_HANDLE_ERROR(apr_brigade_write(ur->bucket_brigade, NULL, NULL,
                                    new_parameter_value, strlen(new_parameter_value)));
  return APR_SUCCESS;
}

// Handles an upload parameter.  If the user didn't select a file, it calls the
// regular porter_handle_parameter function.  For uploads it appends several
// sub-parameters:
//
// * filename:     File name that the user has uploaded.
// * content_type: The content type the browser has provided (sometimes not present).
// * path:         The location of the tempfile where the contents were copied to.
// * signature:    A base64 encoded SHA1 hash of the filename and the PorterSharedSecret.
apr_status_t porter_handle_upload(porter_upload_request_t *ur, apreq_param_t *p)
{
  const char *content_disposition;
  const char *file_name;
  const char *content_type;
  const char *temp_file_path;
  const char *signature;

  apr_size_t size;
  apr_status_t rv;
  apr_finfo_t finfo;

  apr_pool_t *pool  = ur->pool;
  char *escaped_key = apreq_escape(pool, p->v.name, strlen(p->v.name));
  apr_table_t *info = p->info;
  
  PORTER_LOG("Handling Upload");
  PORTER_LOG(p->v.name);

  porter_server_conf *config = (porter_server_conf *)ap_get_module_config(ur->raw_request->server->module_config, &porter_module);

  content_disposition = apr_table_get(info, "content-disposition");
  apreq_header_attribute(content_disposition, "filename", 8, &file_name, &size);

  if (size == 0)
  {
    // There was no file, or at least it had no name, so let's
    // just skip it.
    PORTER_LOG("Appears there was no file, skipping the parameter");
    return APR_SUCCESS;
  }
  PORTER_LOG("Appears there was a file, continuing");
  

  // We know we have a file so push the param name into the array
  // of parameter names so it can be added to the request header.
  *(const char**)apr_array_push(ur->param_names) = p->v.name;

  PORTER_HANDLE_ERROR(porter_append_sub_parameter(pool, ur->bucket_brigade, escaped_key, "filename", file_name, size));

  // content type is optional, and safari doesn't send it if it's unsure.
  content_type = apr_table_get(info, "content-type");
  if (content_type)
  {
    PORTER_HANDLE_ERROR(porter_append_sub_parameter(pool, ur->bucket_brigade, escaped_key, "content_type", content_type, strlen(content_type)));
  }

  // Write the actual upload to disk
  PORTER_HANDLE_ERROR(porter_stream_file_to_disk(pool, p, &finfo));

  // Set appropriate tempfile permissions
  PORTER_HANDLE_ERROR(apr_file_perms_set(finfo.fname, config->permission));

  PORTER_HANDLE_ERROR(porter_append_sub_parameter(pool, ur->bucket_brigade, escaped_key, "path", finfo.fname, strlen(finfo.fname)));

  signature = porter_sign_filename(ur, &finfo);

  PORTER_HANDLE_ERROR(porter_append_sub_parameter(pool, ur->bucket_brigade, escaped_key, "signature", signature, strlen(signature)));
  return APR_SUCCESS;
}


// Returns the base64 hash of the temp file's name and PorterSharedSecret.
char *porter_sign_filename(porter_upload_request_t *ur, apr_finfo_t *finfo)
{
  PORTER_LOG("Signing Filename");
  const char *value_to_hash = apr_pstrcat(ur->pool, finfo->fname, ur->secret, NULL);

  char *hash = apr_palloc(ur->pool, 100 * sizeof(char));

  apr_sha1_base64(value_to_hash, strlen(value_to_hash), hash);
  PORTER_LOG(hash);
  return hash + APR_SHA1PW_IDLEN;
}


// Creates a temporary file and copies the contents of the upload to it.
// Populates finfo with the file info for the temporary file.
apr_status_t porter_stream_file_to_disk(apr_pool_t *pool, apreq_param_t *p,
                                    apr_finfo_t *finfo)
{
  apr_status_t rv;
  apr_file_t *temp_file;
  apr_off_t len;

  PORTER_HANDLE_ERROR(apreq_file_mktemp(&temp_file, pool, NULL));
  PORTER_HANDLE_ERROR(apreq_brigade_fwrite(temp_file, &len, p->upload));
  PORTER_HANDLE_ERROR(apr_file_info_get(finfo, APR_FINFO_NORM, temp_file));

  return APR_SUCCESS;
}

// Appends the sub parameter to the bucket brigade. Sub parameters are given
// 'rails style' with parent_param[sub_param_name]=sub_param_value
apr_status_t porter_append_sub_parameter(apr_pool_t *pool, apr_bucket_brigade *bb,
                                     const char *parent_param,
                                     const char *sub_param,
                                     const char *sub_param_value,
                                     apr_size_t length)
{
  const char *escaped_value = apreq_escape(pool, sub_param_value, length);
  const char *encoded_value = apr_pstrcat(pool, parent_param, "%5B", sub_param, "%5D=", escaped_value, "&", NULL);
  PORTER_LOG("appending sub param");
  PORTER_LOG(sub_param);
  PORTER_LOG(escaped_value);
  return apr_brigade_write(bb, NULL, NULL, encoded_value, strlen(encoded_value));
}
porter_upload_request_t* porter_create_request(apreq_handle_t *req,
                                       request_rec *raw_request,
                                       porter_server_conf *config)
{
  porter_upload_request_t *upload_request  = apr_palloc(req->pool, sizeof(*upload_request));

  upload_request->raw_request    = raw_request;
  upload_request->request        = req;
  upload_request->pool           = req->pool;
  upload_request->param_names    = apr_array_make(req->pool, 1, sizeof(const char*));
  upload_request->status         = APR_SUCCESS;
  upload_request->bucket_brigade = apr_brigade_create(req->pool, req->bucket_alloc);
  upload_request->secret         = config->secret;

  return upload_request;
}


// Apache Config hooks and related functions from here to the end.
static void *porter_create_server_config(apr_pool_t *p, server_rec *s)
{
  porter_server_conf *conf = (porter_server_conf *)apr_pcalloc(p, sizeof(*conf));

  // Disable Porter by default
  conf->enabled = 0;
  conf->minimum_multipart_size = 0;
  conf->permission = 0x0666;

  return conf;
}

static const char* porter_enable_upload(cmd_parms *cmd, void *dir, int argument)
{
  porter_server_conf *config = (porter_server_conf *)ap_get_module_config(cmd->server->module_config, &porter_module);

  config->enabled = argument;
  return NULL;
}

static const char* porter_set_minimum_multipart_size(cmd_parms *cmd, void *dir, const char *argument)
{
  porter_server_conf *config = (porter_server_conf *)ap_get_module_config(cmd->server->module_config, &porter_module);

  const char *error = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

  if (error != NULL) {
    return error;
  }

  config->minimum_multipart_size = apreq_atoi64f(argument);
  return NULL;
}

static const char* porter_set_shared_secret(cmd_parms *cmd, void *dir, const char *argument)
{
  porter_server_conf *config = (porter_server_conf *)ap_get_module_config(cmd->server->module_config, &porter_module);

  const char *error = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

  if (error != NULL) {
    return error;
  }

  config->secret = argument;
  return NULL;
}

static const char* porter_set_file_permission(cmd_parms *cmd, void *dir, const char *argument)
{
  porter_server_conf *config = (porter_server_conf *)ap_get_module_config(cmd->server->module_config, &porter_module);

  const char *error = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

  if (error != NULL) {
    return error;
  }

  config->permission = apr_strtoi64(argument, NULL, 16);
  return NULL;
}

// FIXME Make sure server doesn't start if PorterSharedSecret is not given and Porter is on
static const command_rec porter_commands[] = {
  AP_INIT_FLAG("Porter", porter_enable_upload, NULL, RSRC_CONF, "Enable or Disable the module. Default : Off") ,
  AP_INIT_TAKE1("PorterMinSize", porter_set_minimum_multipart_size, NULL, RSRC_CONF, "Set mininum content length to kick in parsing. Default : 0"),
  AP_INIT_TAKE1("PorterSharedSecret", porter_set_shared_secret, NULL, RSRC_CONF, "Set shared secret for signing parameters."),
  AP_INIT_TAKE1("PorterPermission", porter_set_file_permission, NULL, RSRC_CONF, "Set permission for temporary files. Default : 0x0666"),
  {NULL}
};

static void porter_register_hooks(apr_pool_t *p)
{
  porter_input_filter_handle = ap_register_input_filter("PORTER_INPUT_FILTER", porter_input_filter, NULL, AP_FTYPE_RESOURCE);
  ap_hook_fixups(porter_fixup, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA porter_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    porter_create_server_config,
    NULL,
    porter_commands,
    porter_register_hooks
};
