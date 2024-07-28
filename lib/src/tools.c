#include <bear/tools.h>

/**
 * @brief Convert a GBytes to a hexdump string.
 * @param bytes The GBytes to convert.
 * @return The hexdump string.
 * @note The returned string must be freed with g_free().
 *
 * This function converts a GBytes to a hexdump string. The hexdump string is
 * formatted as follows:
 * ```
 * [00000000]  00 01 02 03 04 05 06 07   08 09 0a 0b 0c 0d 0e 0f   [................]\n"
 * ```
 */
gchar *bear_tools_bytes_to_hex(GBytes *bytes) {
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);

    GString *hex = g_string_new("");
    gchar linestr[16 + 1];

    gint i;
    for (i = 0; i < size; i++) {
        guint8 byte = data[i];

        if (i % 16 == 0) {
            if (i > 0)
                g_string_append_printf(hex, "  [%s]\n", linestr);
            g_string_append_printf(hex, "[%08x]", i);
            memset(linestr, 0, sizeof(linestr));
        }

        if (i % 8 == 0)
            g_string_append_printf(hex, "  ");

        g_string_append_printf(hex, "%02x ", byte);

        linestr[i % 16] = (byte >= 0x20 && byte <= 0x7E) ? byte : '.';
    }

    if (i % 16 != 0) {
        for (int j = i % 16; j < 16; j++) {
            g_string_append_printf(hex, "   ");
            if (j % 8 == 0)
                g_string_append_printf(hex, "  ");
        }
    }

    if (linestr[0])
        g_string_append_printf(hex, "  [%s]\n", linestr);

    return g_string_free(hex, FALSE);
}

static void sanitize_line(gchar *line) {
    // replace all whitespace characters by a single space
    gchar *p = line;
    while (*p) {
        if (g_ascii_isspace(*p))
            *p = ' ';
        p++;
    }
    g_strstrip(line);

    // detect a prefix and blank it out. prefixes can be "0x{hex}:", "{hex}:" or {hex} surrounded by any form of
    // parenthesis (e.g. "[{hex}]").
    // generally speaking, if the first non-blank character is not a hex digit, we have a prefix
    p = line;
    if (!g_ascii_isxdigit(*p)) {
        // blank out anything up to the first blank
        while (*p && *p != ' ')
            *p++ = ' ';
    }
    g_strstrip(line);

    p = line;
    // if the line matches "^(0x|0X)?[0-9a-fA-F]{2,}: ", blank it out
    const char *regex = "^(0x|0X)?[0-9a-fA-F]{2,}: ";
    GRegex *re = g_regex_new(regex, 0, 0, NULL);
    GMatchInfo *match_info;
    if (g_regex_match(re, p, 0, &match_info)) {
        gchar *match = g_match_info_fetch(match_info, 0);
        gsize len = g_utf8_strlen(match, -1);
        for (gsize i = 0; i < len; i++)
            *p++ = ' ';
        g_free(match);
        g_strstrip(line);
    }

    // at this point, assume we got rid of all prefixes. now let's deal with suffixes:
    // find the first character that is not "0x", "0X", a blank or a hex digit, and terminate the string there
    p = line;
    while (*p) {
        if (g_str_has_prefix(p, "0x") || g_str_has_prefix(p, "0X"))
            p += 2;
        else if (g_ascii_isxdigit(*p) || *p == ' ')
            p++;
        else {
            *p = 0;
            break;
        }
    }
    g_strstrip(line);
}

/**
 * @brief Convert a hexdump string to a GBytes.
 * @param hex A hexdump string. A wide variety of possible formats are supported. See test cases for examples.
 * @return The GBytes, or NULL if parsing failed.
 * @note The returned GBytes must be freed with g_bytes_unref().
 */
GBytes *bear_tools_hex_to_bytes(const gchar *hex) {
    GByteArray *byte_array = g_byte_array_new();

    gchar **lines = g_strsplit(hex, "\n", -1);
    for (gchar **line = lines; *line; line++) {

        sanitize_line(*line);

        gchar *p = *line;
        do {
            // if p points to "0x" or "0X", skip it
            if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X'))
                p += 2;

            // if p points to 2 hex characters, we have a byte
            if (g_ascii_isxdigit(p[0]) && g_ascii_isxdigit(p[1])) {
                guint8 byte = 0;
                for (int i = 0; i < 2; i++) {
                    byte <<= 4;
                    if (g_ascii_isdigit(*p))
                        byte |= *p - '0';
                    else if (*p >= 'a' && *p <= 'f')
                        byte |= *p - 'a' + 10;
                    else if (*p >= 'A' && *p <= 'F')
                        byte |= *p - 'A' + 10;
                    else
                        break;
                    p++;
                }
                g_byte_array_append(byte_array, &byte, 1);
            } else
                p++;
        } while (*p);
    }

    g_strfreev(lines);
    return g_byte_array_free_to_bytes(byte_array);
}