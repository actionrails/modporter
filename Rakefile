# You may need to adjust the path here.
APREQ_INCLUDES = `apreq2-config --includes`.strip
# The location of your apache include directory.  The apreq module
# header file should be in here.
APACHE_INCLUDE ="/usr/include/apache2"
# This is called apxs2 in some distributions.
APXS           = "apxs"

task :default do
  `#{APXS} -i -c #{APREQ_INCLUDES} -I#{APACHE_INCLUDE}-i mod_porter.c`
end

task :debug_build do
  `#{APXS} -i -c #{APREQ_INCLUDES} -I#{APACHE_INCLUDE} -DPORTER_DEBUG -i mod_porter.c`
end

task :build_mac do
  `#{APXS} -i -c -Wc,-arch -Wc,x86_64 -Wl,-arch -Wl,x86_64 #{APREQ_INCLUDES} -I#{APACHE_INCLUDE} mod_porter.c`
end
