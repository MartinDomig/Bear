#include <bear/tools.h>

gchar *bear_hexdump(GBytes *bytes) {
  GString *hex = g_string_new("");
  guint offset = 0;
  gsize size;
  const guint8 *data = g_bytes_get_data(bytes, &size);
  for (gsize i = 0; i < size; i++) {
    guint8 byte = data[i];

    if (i % 16 == 0) {
      if (i > 0)
        g_string_append_printf(hex, "\n");
      g_string_append_printf(hex, "%08x ", offset);
      offset += 16;
    }

    if (i % 8 == 0)
      g_string_append_printf(hex, "  ");

    // if byte is a printable ASCII character, append it to the string
    if (byte >= 0x20 && byte <= 0x7E)
      g_string_append_printf(hex, "[%c]", byte);
    else
      g_string_append_printf(hex, " %02x", byte);
  }

  return g_string_free(hex, FALSE);
}
