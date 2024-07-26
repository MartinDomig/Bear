wolfprot_sources = files([
  'wolfprot.c',
])

wolfprot_deps = [libbear_dep, glib_dep]

executable('wolfprot',
           wolfprot_sources,
           dependencies : wolfprot_deps,
           c_args: '-DG_LOG_DOMAIN="wolfprot"',
           build_by_default: true,
           install : false)
