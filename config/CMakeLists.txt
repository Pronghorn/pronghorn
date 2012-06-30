CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(config)

FILE(GLOB config_files *.conf.template)
  FOREACH(config_file ${config_files})
  STRING(LENGTH ${config_file} config_file_length)
  MATH(EXPR short_config_file_length "${config_file_length} - 9")
  STRING(SUBSTRING ${config_file} 0 ${short_config_file_length} short_config_file)

  MESSAGE(STATUS "Configuring config file ${short_config_file}")
  CONFIGURE_FILE(${config_file} ${short_config_file} @ONLY)
  INSTALL(FILES ${short_config_file} DESTINATION ${PRONGHORN_CONFIG_DIRECTORY} PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
ENDFOREACH()

