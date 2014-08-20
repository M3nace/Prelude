/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include "alert-prelude.h"
#include "motion.h"

/**
 * \brief Initialize analyzer description
 *
 * \return 0 if ok
 */
static int SetupAnalyzer(idmef_analyzer_t *analyzer)
{
  int ret;
  prelude_string_t *string;

  ret = idmef_analyzer_new_model(analyzer, &string);
  if ( ret < 0 )
    return (ret);
  prelude_string_set_constant(string, ANALYZER_MODEL);

  ret = idmef_analyzer_new_class(analyzer, &string);
  if ( ret < 0 )
    return (ret);
  prelude_string_set_constant(string, ANALYZER_CLASS);

  ret = idmef_analyzer_new_manufacturer(analyzer, &string);
  if ( ret < 0 )
    return (ret);
  prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

  ret = idmef_analyzer_new_version(analyzer, &string);
  if ( ret < 0 )
    return (ret);
  prelude_string_set_constant(string, VERSION);

  return (0);
}


int	AlertPrelude (AlertPreludeCtx *ctx, struct image_data *image)
{
  int			ret;
  idmef_time_t		*time = NULL;
  idmef_alert_t		*alert = NULL;
  prelude_string_t	*str = NULL;
  idmef_message_t	*idmef = NULL;
  idmef_classification_t	*class = NULL;

  ret = idmef_message_new(&idmef);
  if ( ret < 0 )
    return (ret);

  ret = idmef_message_new_alert(idmef, &alert);
  if ( ret < 0 )
    return (ret);

  ret = idmef_alert_new_classification(alert, &class);
  if ( ret < 0 )
    return (ret);

  ret = idmef_classification_new_text(class, &str);
  if ( ret < 0 )
    return (ret);

  prelude_string_set_ref(str, "Motion detected !");

  ret = idmef_alert_new_detect_time(alert, &time);
  if ( ret < 0 )
    return (ret);

  ret = idmef_time_new_from_gettimeofday(&time);
  if ( ret < 0 )
    return (ret);

  idmef_alert_set_create_time(alert, time);

  /* finally, send event */
  prelude_client_send_idmef(ctx->client, idmef);

  return (0);
}

/**
 * \brief Clean the prelude client contain the ctx pointer
 */

static void AlertPreludeDeinitCtx(AlertPreludeCtx *ctx)
{
    prelude_client_destroy(ctx->client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
}

/**
 * \brief Initialize the Prelude logging module: initialize
 * library, create the client and try to establish the connection
 * to the Prelude Manager.
 * Client flags are set to force asynchronous (non-blocking) mode for
 * both alerts and heartbeats.
 * This function requires an existing Prelude profile to work.
 *
 * \return A newly allocated AlertPreludeCtx structure, or NULL
 */
AlertPreludeCtx *AlertPreludeInitCtx(void)
{
  int ret;
  prelude_client_t *client;
  AlertPreludeCtx *ctx;
  const char *prelude_profile_name;

  ret = prelude_init(0, NULL);
  if ( ret < 0 ) {
    prelude_perror(ret, "unable to initialize the prelude library");
    return (NULL);
  }

  prelude_profile_name = DEFAULT_PRELUDE_PROFILE;

  ret = prelude_client_new(&client, prelude_profile_name);
  if ( ret < 0 || ! client ) {
    prelude_perror(ret, "Unable to create a prelude client object");
    prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    return (NULL);
  }

  ret = prelude_client_set_flags(client, prelude_client_get_flags(client) | PRELUDE_CLIENT_FLAGS_ASYNC_TIMER|PRELUDE_CLIENT_FLAGS_ASYNC_SEND);
  if ( ret < 0 ) {
    prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    return (NULL);
  }

  ret = SetupAnalyzer(prelude_client_get_analyzer(client));
  if ( ret < 0 ) {
    prelude_perror(ret, "Unable to setup the analyzer");
    prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    return (NULL);
  }

  ret = prelude_client_start(client);
  if ( ret < 0 ) {
    prelude_perror(ret, "Unable to start prelude client");
    prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    return (NULL);
  }

  ctx = mymalloc(sizeof(AlertPreludeCtx));
  if ( ctx == NULL ) {
    prelude_perror(ret, "Unable to allocate memory");
    prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    return (NULL);
  }

  ctx->client = client;
  ctx->clean_fct = &AlertPreludeDeinitCtx;

  return (ctx);
}
