/**
 * @file mod_ezshopping.c
 * @author Tim Cooijmans
 *
 * EZShopping module to replace frontend.php.  Tries a request on multiple
 * (configurable) path templates.
 */

#include <unistd.h>

#include "httpd.h"
#include "http_core.h"
#include "http_request.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"


/* main hook */
static int ez_translate_name(request_rec *r);

/* configuration directive hooks */
static const char *ez_config_add_path		(cmd_parms* parms, void *dircfg, const char *arg);
static const char *ez_config_add_php_path	(cmd_parms* parms, void *dircfg, const char *arg);
static const char *ez_config_404_shop		(cmd_parms* parms, void *dircfg, const char *arg);
static const char *ez_config_404_file		(cmd_parms* parms, void *dircfg, const char *arg);
static const char *ez_config_403_denied		(cmd_parms* parms, void *dircfg, const char *arg);
static const char *ez_config_shop_dir_root	(cmd_parms* parms, void *dircfg, const char *arg);
static const char *ez_config_shop_link_root	(cmd_parms* parms, void *dircfg, const char *arg);
static const char *ez_config_enable		(cmd_parms* parms, void *dircfg, int on);

static void *ez_create_server_config(apr_pool_t *pool, server_rec *svr);
static void ez_register_hooks(apr_pool_t *p);



/**
 * @brief The configuration directives we take
 */
static const command_rec ez_config_directives[] = {
	AP_INIT_FLAG	("EZShopping",		ez_config_enable,		NULL, RSRC_CONF, "Enable the EZShopping rewriter"),
	AP_INIT_TAKE1	("EZShop403Denied",	ez_config_403_denied,		NULL, RSRC_CONF, "Access denied"),
	AP_INIT_TAKE1	("EZShop404Shop",	ez_config_404_shop,		NULL, RSRC_CONF, "Shop Not Found error document"),
	AP_INIT_TAKE1	("EZShop404File",	ez_config_404_file,		NULL, RSRC_CONF, "File Not Found error document"),
	AP_INIT_TAKE1	("EZShopLinkRoot",	ez_config_shop_link_root,	NULL, RSRC_CONF, "Directory containing shop links"),
	AP_INIT_TAKE1	("EZShopDirRoot",	ez_config_shop_dir_root,	NULL, RSRC_CONF, "Directory containing shop dirs"),
	AP_INIT_TAKE1	("EZAddPath",		ez_config_add_path,		NULL, RSRC_CONF, "Add a path to check for file existence"),
	AP_INIT_TAKE1	("EZAddPHPPath",	ez_config_add_php_path,		NULL, RSRC_CONF, "Add a path to check for file existence and can run PHP files"),
	{ NULL }
};

/**
 * @brief Tells Apache about our module
 *
 * @note Name should be \<module name\>_module.
 */
module AP_MODULE_DECLARE_DATA mod_ezshopping_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	ez_create_server_config,
	NULL,
	ez_config_directives,
	ez_register_hooks,
};

/**
 * @brief Linked structure to hold a path template.
 */
typedef struct ez_path_t ez_path_t;
struct ez_path_t
{
	/**
	 * @brief Indicates whether this path template contained a %s token.
	 *
	 * Used to determine whether a shop environment variable needs to
	 * be set.
	 *
	 * @note This will only be set after the path template has been parsed.
	 */
	int is_shop_path;

	/**
	 * @brief Set to TRUE
	 *
	 * When set to 1 PHP files are allowed to be ran
	 */
	int is_php_path;

	/**
	 * @brief The path template.
	 *
	 * Can contain the following tokens:
	 * <dl>
	 * 	<dt><code>%s</code></dt>
	 * 	<dd>shop name</dd>
	 * </dl>
	 */
	const char *path;

	/**
	 * @brief Pointer to next path template.
	 */
	ez_path_t *next;
};

/**
 * @brief Server configuration struct
 */
struct ez_server_config_t
{
	char enabled; /**< Whether mod_ezshopping is enabled for this server */

	const char *shop404; /**< Custom shop not found error document */
	const char *file404; /**< Custom file not found error document */
	const char *denied403; /**< Access denied to file */

	const char *shop_dir_root;  /**< Directory with shop dirs */
	const char *shop_link_root; /**< Directory with hostname->shop links */

	ez_path_t *paths; /**< Linked list of path templates to try */
};
typedef struct ez_server_config_t ez_server_config_t;

///**
// * @brief Global pointer to server config
// */
//static ez_server_config_t *ez_server_config;

/**
 * @brief Request info
 */
struct ez_req_info_t {
	char *shop; /**< Shop name */
	char *path; /**< Path leftover after stripping shop name */
};
typedef struct ez_req_info_t ez_req_info_t;

/**
 * @brief Get a file's type
 *
 * @param pool An APR memory pool
 * @param path The path to the file
 * @return The file type
 */
static apr_filetype_e ez_file_type(apr_pool_t *pool, const char *path)
{
	apr_finfo_t sbuf;
	apr_status_t check;

	check = apr_stat(&sbuf, path, APR_FINFO_TYPE, pool);
	if (check == APR_SUCCESS)
	        return sbuf.filetype;
	else
		return APR_UNKFILE;
}

/**
 * @brief Find out whether a file is a directory
 *
 * @param pool An APR memory pool
 * @param path The path to the file
 * @return true or false
 */
static int ez_is_dir(apr_pool_t *pool, const char *path)
{
	return (ez_file_type(pool, path) == APR_DIR);
}

/**
 * @brief Find out whether a path exists
 *
 * @param pool An APR memory pool
 * @param path The path
 * @return true or false
 */
static int ez_path_exists(apr_pool_t *pool, const char *path) {
	apr_filetype_e type = ez_file_type(pool, path);

	if (type != 0 && type != APR_UNKFILE)
		return 1;

	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool, "`%s' does not exist", path);
	return 0;
}

/**
 * @brief Extract the hostname part from an uri
 *
 * @param pool An APR pool
 * @param uri The uri to parse
 * @return The hostname
 */
static char *ez_get_hostname_from_uri(apr_pool_t *pool, const char *uri)
{
	apr_uri_t *parsed_uri = apr_palloc(pool, sizeof(*parsed_uri));
	memset(parsed_uri, 0, sizeof(*parsed_uri));

	/*
	 * According to the (scarce) documentation, apr_uri_parse
	 * returns an HTTP status code...  WTF?
	 *
	 * parsed_uri->hostname will probably be NULL if it fails, so don't
	 * bother checking the return value.
	 */
	apr_uri_parse(pool, uri, parsed_uri);

	return parsed_uri->hostname;
}

/**
 * @brief Find out what shop belongs to this hostname
 *
 * @param pool The pool
 * @param hostname The hostname
 */
static char *ez_get_shop_name_from_hostname(request_rec *r, const char *hostname)
{
	int ret;
	char *link = NULL;
	char *shop_name = NULL;
	ez_server_config_t *ez_conf;

	ez_conf = (ez_server_config_t *)ap_get_module_config (r->server->module_config, &mod_ezshopping_module);

	link = apr_pstrcat(r->pool, ez_conf->shop_link_root, "/", hostname, NULL);

	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, r->pool, "reading link `%s'... ", link);

	shop_name = apr_palloc(r->pool, 256);
	ret = readlink(link, shop_name, 255);
	if (ret == -1) {
		ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, r->pool, "failed");
		return NULL;
	}
	shop_name[ret] = '\0';
	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, r->pool, "`%s'", shop_name);

	return shop_name;
}

/**
 * @brief Check whether the shop exists or not
 *
 * @param pool An APR pool
 * @param shop The shop name
 * @return true or false
 */
static int ez_shop_exists(request_rec *r, const char *shop) {
	ez_server_config_t *ez_conf;

	if (!shop || shop[0] == '\0')
		return 0;

	ez_conf = (ez_server_config_t *)ap_get_module_config (r->server->module_config, &mod_ezshopping_module);
	char *path = apr_pstrcat(r->pool, ez_conf->shop_dir_root, "/", shop, NULL);

	return ez_is_dir(r->pool, path);
}

/**
 * @brief Parse a request and fill an ez_req_info_t struct
 *
 * @param r The request
 * @return The extracted request info
 */
static ez_req_info_t ez_get_req_info(request_rec *r)
{
	ez_req_info_t req_info;
	memset(&req_info, 0, sizeof(req_info));

	const char *ezshopping_hdr = apr_table_get(r->headers_in, "VHOST");

	if (ezshopping_hdr && !strstr(ezshopping_hdr, ".ezshopping.nl")) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "getting info from the ezshopping header `%s'...", ezshopping_hdr);

		char *hostname = NULL;
		if (strchr(ezshopping_hdr, '/')) {
			hostname = ez_get_hostname_from_uri(r->pool,
					ezshopping_hdr);
			if (!hostname) {
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, HTTP_INTERNAL_SERVER_ERROR, r, "ez_get_hostname_from_uri failed");
				goto out;
			}
		} else {
			/*
			 * With no slashes, we can be pretty sure it's a
			 * hostname.  Good enough for now.
			 */
			hostname = apr_pstrdup(r->pool, ezshopping_hdr);
		}
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "got hostname `%s'", hostname);

		req_info.shop = ez_get_shop_name_from_hostname(r, hostname);
		if (!req_info.shop) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ez_get_shop_name_from_hostname failed");
			goto out;
		}

		req_info.path = apr_pstrdup(r->pool, r->uri);
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "getting info from uri `%s'...", r->uri);

		char *uri = r->uri;

		/* Skip leading slashes */
		while (*uri == '/')
			uri++;

		req_info.path = strchr(uri, '/');
		if (req_info.path) {
			/* Format is "<shop></path>" */
			req_info.shop = apr_pstrndup(r->pool, uri,
							req_info.path - uri);
			req_info.path = apr_pstrdup(r->pool, req_info.path);
		} else {
			/* Format is "<shop>" */
			req_info.shop = apr_pstrdup(r->pool, uri);
			req_info.path = apr_pstrdup(r->pool, "");
		}

		/* Nevermind if it isn't a shop */
		if (!ez_shop_exists(r, req_info.shop)) {
			req_info.shop = NULL;
			req_info.path = r->uri;
		}
	}

out:
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "shop: `%s', path: `%s'", req_info.shop, req_info.path);

	return req_info;
}

/**
 * @brief Parse a path template and replace tokens
 *
 * A path template can contain the following tokens, which will be replaced by
 * runtime values:
 * <dl>
 * 	<dt><code>%s</code></dt>
 * 	<dd>shop name</dd>
 * </dl>
 *
 * @param pool An APR pool
 * @param req_info Request information
 * @param path The path template
 * @return The expanded path template string
 */
static char *ez_expand_path_template(apr_pool_t *pool,
				ez_req_info_t req_info, ez_path_t *path)
{
	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool, "expanding path template `%s'...", path->path);

	const char *path_template = path->path;
	char *replacement = NULL;
	char *token = strchr(path_template, '%');

	if (!token) {
		ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool, "no tokens to replace");
		return apr_pstrdup(pool, path_template);
	}

	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool, "found token `%%%c'", token[1]);
	switch (token[1]) {
		case 's':
			/* shop name */
			path->is_shop_path = 1;
			replacement = req_info.shop;
			break;
		case '%':
			/* literal % */
			replacement = apr_pstrdup(pool, "%");
			break;
		case '\0':
			/* unthinkable mayhem if we recurse after this */
			return apr_pstrdup(pool, path_template);
			break;
		default:
			/* don't touch the string */
			replacement = apr_pstrndup(pool, token, 2);
			ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool, "unknown token `%s'", replacement);
			break;
	}

	char *first_part = apr_pstrndup(pool, path_template,
						token - path_template);
	char *second_part = token + 2;

	/*
	 * Create a struct to pass to recursive call.  There's no way to find
	 * out whether the recursive call encountered a %s token, other than
	 * passing this struct along.
	 */
	ez_path_t *rest = apr_palloc(pool, sizeof(*rest));
	memset(rest, 0, sizeof(*rest));
	rest->path = second_part;

	char *result = apr_pstrcat(pool, first_part, replacement,
			ez_expand_path_template(pool, req_info, rest), NULL);
	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool, "result: `%s'", result);

	/* Merge the results */
	path->is_shop_path |= rest->is_shop_path;

	return result;
}

/**
 * @brief Test a path template
 *
 * @param r The request
 * @param req_info The request info
 * @param path The path template
 *
 * @return An HTTP status code
 * @retval HTTP_NOT_FOUND The file or shop was not found
 * @retval HTTP_FORBIDDEN The file IS found, but not accessible (php file in non-php dir)
 * @retval HTTP_OK The file was found
 */
static int ez_try(request_rec *r, ez_req_info_t req_info, ez_path_t *path)
{
	ez_server_config_t *ez_conf;
	ez_conf = (ez_server_config_t *)ap_get_module_config (r->server->module_config, &mod_ezshopping_module);

	char *base_path = ez_expand_path_template(r->pool, req_info, path);

	char *final_path = apr_pstrcat(r->pool, base_path, req_info.path, NULL);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "trying path `%s'...", final_path);

	/* is_shop_path is only set AFTER the ez_expand_path_template() call */
	if (path->is_shop_path) {
		/* Set shop environment variable */
		apr_table_set(r->subprocess_env, "SHOPNAME",
				req_info.shop ? req_info.shop : "");
	}

	if (ez_path_exists(r->pool, final_path)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "hit `%s' as `%s'", r->uri, final_path);
		r->filename = final_path;

		if (strstr (final_path, ".php") && path->is_php_path == 0) 
		{
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "PHP %s %d",  final_path, path->is_php_path);
			r->status = HTTP_FORBIDDEN;
			r->filename = apr_pstrcat(r->pool, ap_document_root(r), ez_conf->denied403, NULL);
			return HTTP_FORBIDDEN;
		}
		return HTTP_OK;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "missed `%s' as `%s'", r->uri, final_path);

	/* try with .php after first path element */
	char *first_elm = req_info.path;
	char *after_first_elm = strchr(req_info.path, '/');
	if (after_first_elm == req_info.path)
		/* it started with a slash */
		after_first_elm = strchr(req_info.path+1, '/');
	if (after_first_elm)
		first_elm = apr_pstrndup(r->pool, req_info.path,
				after_first_elm - req_info.path);

	final_path = apr_pstrcat(r->pool, base_path, first_elm, ".php", NULL);

	if (ez_path_exists(r->pool, final_path)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "hit `%s' as `%s'", r->uri, final_path);
		if (strstr (final_path, ".php")  && path->is_php_path == 0) 
		{
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "PHP %s %d",  final_path, path->is_php_path);
			r->status = HTTP_FORBIDDEN;
			r->filename = apr_pstrcat(r->pool, ap_document_root(r), ez_conf->denied403, NULL);
			return HTTP_FORBIDDEN;
		}
		r->filename = apr_pstrcat(r->pool, final_path,
						after_first_elm, NULL);
		return HTTP_OK;
	}

	return HTTP_NOT_FOUND;
}

/**
 * @brief Test all configured path templates
 *
 * @param r The request
 *
 * @return An HTTP status code
 * @retval HTTP_NOT_FOUND File or shop not found
 * @retval HTTP_OK File found
 */
static int ez_try_paths(request_rec *r)
{
	ez_server_config_t *ez_conf;

	ez_conf = (ez_server_config_t *)ap_get_module_config (r->server->module_config, &mod_ezshopping_module);
	ez_req_info_t req_info = ez_get_req_info(r);

	if (!ez_shop_exists(r, req_info.shop)) {
		r->status = HTTP_NOT_FOUND;
		r->filename = apr_pstrcat(r->pool, ap_document_root(r), ez_conf->shop404, NULL);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "shop not found (%s)", r->filename);

		return HTTP_NOT_FOUND;
	}

	ez_path_t *path = ez_conf->paths;
	if (!path)
		return HTTP_NOT_FOUND;

	/* Try paths */
	do {
		int ret = ez_try(r, req_info, path);
		if (ret == HTTP_OK || ret == HTTP_FORBIDDEN) return ret;
	} while ((path = path->next) != NULL);

	/* Fallthrough. Nothing found */
	r->status = HTTP_NOT_FOUND;
	r->filename = apr_pstrcat(r->pool, ap_document_root(r),
					ez_conf->file404, NULL);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "file not found (%s)", r->filename);

	return HTTP_NOT_FOUND;
}

/**
 * @brief Rewrite hook
 *
 * Main Apache hook to rewrite request URI/filename.
 */
static int ez_translate_name(request_rec *r)
{
	ez_server_config_t *ez_conf;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ez_translate: %s", r->uri);

	ez_conf = (ez_server_config_t *)ap_get_module_config (r->server->module_config, &mod_ezshopping_module);
	if (!ez_conf->enabled)
		return DECLINED;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "config enabled");

	/* check in docroot first */
	char *path = apr_pstrcat(r->pool, ap_document_root(r), r->uri, NULL);
	if (!ez_path_exists(r->pool, path)) {
		ez_try_paths(r);
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "hit `%s' in document root", r->uri);
		r->filename = path;
	}

	/* r->filename and r->status will be set by ez_try_paths */

	return OK;
}

/**
 * @brief Enable or disable mod_ezshopping
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param on true to enable, false to disable
 */
static const char *ez_config_enable(cmd_parms* parms, void *dircfg, int on)
{
	ez_server_config_t *ez_conf;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "EZShopping %sabled for server %s", on ? "en" : "dis", parms->server->server_hostname);

	ez_conf = (ez_server_config_t *)ap_get_module_config (parms->server->module_config, &mod_ezshopping_module);
	ez_conf->enabled = on;

	return NULL;
}

/**
 * @brief Specify a custom 403 Access denied
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param arg The path to the document
 */
static const char *ez_config_403_denied(cmd_parms* parms, void *dircfg, const char *arg)
{
	ez_server_config_t *ez_conf;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "setting 403 Denied document to `%s'", arg);

	ez_conf = (ez_server_config_t *)ap_get_module_config (parms->server->module_config, &mod_ezshopping_module);
	ez_conf->denied403 = arg;

	return NULL;
}

/**
 * @brief Specify a custom 404 File Not Found document
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param arg The path to the document
 */
static const char *ez_config_404_file(cmd_parms* parms, void *dircfg, const char *arg)
{
	ez_server_config_t *ez_conf;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "setting 404 File Not Found document to `%s'", arg);

	ez_conf = (ez_server_config_t *)ap_get_module_config (parms->server->module_config, &mod_ezshopping_module);
	ez_conf->file404 = arg;

	return NULL;
}

/**
 * @brief Specify a custom 404 Shop Not Found document
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param arg The path to the document
 */
static const char *ez_config_404_shop(cmd_parms* parms, void *dircfg, const char *arg)
{
	ez_server_config_t *ez_conf;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "setting 404 Shop Not Found document to `%s'", arg);
	
	ez_conf = (ez_server_config_t *)ap_get_module_config (parms->server->module_config, &mod_ezshopping_module);
	ez_conf->shop404 = arg;

	return NULL;
}

/**
 * @brief Specify the directory that holds hostname->shop links
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param arg The path to the directory
 */
static const char *ez_config_shop_link_root(cmd_parms* parms, void *dircfg, const char *arg)
{
	ez_server_config_t *ez_conf;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "setting shop link root to `%s'", arg);

	ez_conf = (ez_server_config_t *)ap_get_module_config (parms->server->module_config, &mod_ezshopping_module);
	ez_conf->shop_link_root = arg;

	return NULL;
}

/**
 * @brief Specify the directory that holds shop directories
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param arg The path to the directory
 */
static const char *ez_config_shop_dir_root(cmd_parms* parms, void *dircfg, const char *arg)
{
	ez_server_config_t *ez_conf;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "setting shop dir root to `%s'", arg);

	ez_conf = (ez_server_config_t *)ap_get_module_config (parms->server->module_config, &mod_ezshopping_module);
	ez_conf->shop_dir_root = arg;

	return NULL;
}

/**
 * @brief Internal add path, used by ez_config_add_path and ez_config_add_php_path
 *
 */
static const char *ez_internal_add_path(cmd_parms* parms, void *dircfg, const char *arg, int is_php_path)
{
	ez_server_config_t *ez_conf;

	ez_conf = (ez_server_config_t *)ap_get_module_config (parms->server->module_config, &mod_ezshopping_module);

	ez_path_t *path = NULL;
	if (ez_conf->paths) {
		path = ez_conf->paths;
		while (path->next != NULL)
			path = path->next;

		path->next = apr_palloc(parms->pool, sizeof(*path->next));
		path = path->next;
	} else {
		ez_conf->paths = apr_palloc(parms->pool,
					sizeof(*ez_conf->paths));
		path = ez_conf->paths;
	}
	memset(path, 0, sizeof(*path));

	path->path = arg;
	path->is_php_path = is_php_path;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "added new %s path `%s'", is_php_path?"php":"", path->path);

	return NULL;
}

/**
 * @brief Add a PHP path to the path template list.
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param arg The path template to add
 */
static const char *ez_config_add_php_path(cmd_parms* parms, void *dircfg, const char *arg)
{
	return ez_internal_add_path (parms, dircfg, arg, 1);
}

/**
 * @brief Add a path to the path template list.
 *
 * @param parms Only server member is used
 * @param dircfg Not used
 * @param arg The path template to add
 */
static const char *ez_config_add_path (cmd_parms* parms, void *dircfg, const char *arg) {
	return ez_internal_add_path (parms, dircfg, arg, 0);
}

/**
 * @brief Allocate and setup a server config struct
 *
 * @note Server config will be stored in ez_server_config global.
 */
static void *ez_create_server_config(apr_pool_t *pool, server_rec *svr)
{
	ez_server_config_t *ez_server_config;

	/* Allocate memory for per-server configuration */
	ez_server_config = apr_palloc(pool, sizeof(*ez_server_config));
	memset(ez_server_config, 0, sizeof(*ez_server_config));

	return (void *)ez_server_config;
}

/**
 * @brief Register hooks with Apache
 */
static void ez_register_hooks(apr_pool_t *p)
{
	ap_hook_translate_name(ez_translate_name, NULL, NULL, APR_HOOK_FIRST);
}

