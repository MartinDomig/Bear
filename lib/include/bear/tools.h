#pragma once

#include <glib.h>

G_BEGIN_DECLS

gchar *bear_tools_bytes_to_hex(GBytes *bytes);
GBytes *bear_tools_hex_to_bytes(const gchar *hex);
gchar *bear_tools_bytes_squash(const gchar *hex);

G_END_DECLS
