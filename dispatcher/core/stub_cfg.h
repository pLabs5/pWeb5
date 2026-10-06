#pragma once

/* Not part of dRPC5. The bundled dns resolver originally read its server
 * list out of its config file. There is no config file in the dispatcher,
 * so this stub says "unset" and dns.c falls back to the defaults. */
int cfg_get(const char *key, char *out, unsigned long cap);
