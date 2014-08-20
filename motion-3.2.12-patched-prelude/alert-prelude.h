#ifndef _PRELUDE_H_
# define _PRELUDE_H_

#include <libprelude/prelude.h>

#define ANALYZER_CLASS "MIDS"
#define ANALYZER_MODEL "Motion"
#define ANALYZER_MANUFACTURER "http://www.lavrsen.dk/foswiki/bin/view/Motion/WebHome"
#define ANALYZER_SID_URL "http://www.lavrsen.dk/foswiki/bin/view/Motion/WebHome"

#define DEFAULT_ANALYZER_NAME "Motion"

#define DEFAULT_PRELUDE_PROFILE "motion"

/**
 * This holds global structures and variables. Since libprelude is thread-safe,
 * there is no need to store a mutex.
 */
typedef struct AlertPreludeCtx_ {
  /** The client (which has the send function) */
  prelude_client_t *client;
  void (*clean_fct)(struct AlertPreludeCtx_ *);
  
} AlertPreludeCtx;
/**
 * This holds per-thread specific structures and variables.
 */
typedef struct AlertPreludeThread_ {
  /** Pointer to the global context */
  AlertPreludeCtx *ctx;
} AlertPreludeThread;


struct image_data;

AlertPreludeCtx	*AlertPreludeInitCtx(void);
int		AlertPrelude (AlertPreludeCtx *, struct image_data *);

#endif /*!_PRELUDE_H_*/
