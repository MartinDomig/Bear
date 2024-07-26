pkg = import('pkgconfig')
gnome = import('gnome')

mkenum_sources = []

subdir('include')

bear_includedir = get_option('prefix') / get_option('includedir') / 'bear'
install_headers(libbear_headers, install_dir : bear_includedir)

bear_sub_includedir = join_paths(bear_includedir, 'bear')
install_headers(libbear_sub_headers, install_dir : bear_sub_includedir)

libbear_sources = []
subdir('src')

libbear_include = [ include_directories('include') ]

libbear_deps = [
    glib_dep,
]

build_sources = libbear_sources + mkenum_sources
build_include = libbear_include + include_directories('include/bear')

libbear = library('bear',
    build_sources,
    include_directories : build_include,
    dependencies : libbear_deps,
    version : meson.project_version(),
    c_args: [
        '-DG_LOG_DOMAIN="bear"',
        '-DBEAR_COMPILATION'
    ],
    install : true)

libbear_dep = declare_dependency(
    link_with : libbear,
    include_directories: libbear_include)

pkg.generate(libbear,
    name: 'bear',
    description: 'Fuzzy Bear',
    libraries: [ glib_dep ],
    subdirs: [ 'bear' ],
)

subdir('tests')
