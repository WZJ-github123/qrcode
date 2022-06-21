# cmake needs this line
cmake_minimum_required(VERSION 3.1)

# Define project name
project(QRcode)

# Find OpenCV, you may need to set OpenCV_DIR variable
# to the absolute path to the directory containing OpenCVConfig.cmake file
# via the command line or GUI


# If the package has been found, several variables will
# be set, you can find the full list with descriptions
# in the OpenCVConfig.cmake file.
# Print some message showing some of them

# Declare the executable target built from your sources
add_executable(qrcode qrcode1.cpp )

# Link your application with OpenCV libraries
target_link_libraries(qrcode ${catkin_LIBRARIES} libcryptopp.so -lcryptopp -lpthread)

