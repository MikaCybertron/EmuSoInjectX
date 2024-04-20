file(GLOB EMUINJ_SRC *.cpp)

add_executable(emuinj ${EMUINJ_SRC})

target_link_libraries(emuinj ELFPP)