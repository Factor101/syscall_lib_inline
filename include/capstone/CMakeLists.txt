add_library(capstone "")
set_target_properties(capstone PROPERTIES LINKER_LANGUAGE CXX)

target_sources(capstone PUBLIC
	${CMAKE_CURRENT_LIST_DIR}/capstone.h
)
target_include_directories(capstone PUBLIC 
	${CMAKE_CURRENT_LIST_DIR}
)