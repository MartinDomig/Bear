libbear_sub_headers = files(
    'options.h',
    'fuzzer.h',
    'fuzzy-value.h',
    'tools.h',
)

mkenum_sources += gnome.mkenums_simple('bear-enums',
  sources: libbear_sub_headers,
  symbol_prefix: 'BEAR_ENUM',
  install_header: true,
  install_dir: 'bear',
)
