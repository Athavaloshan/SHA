#Compiler flags
CXX_FLAGS := -Wall -Wno-sign-compare -std=c++17

# Project directory structure
BIN := bin
SRC := src
TEST_SRC:= test
INC := ./

# Build directories and output
TARGET := $(BIN)/sha256.a
TARGET_TEST := $(BIN)/test
BUILD := build

# Library search directories and flags
LDFLAGS := /usr/lib/libgtest.a /usr/lib/libgtest_main.a -lpthread

# Include directories
INC_FLAGS := -I./src 

# Construct build output and dependency filenames
SRCS = $(shell find $(SRC) -name "*.cpp")
TEST_SRCS = $(shell find $(TEST_SRC) -name "*.cpp")
OBJS := $(subst $(SRC)/,$(BUILD)/,$(addsuffix .o,$(basename $(SRCS))))
TEST_OBJS = $(subst $(TEST_SRC)/,$(BUILD)/,$(addsuffix .o,$(basename $(TEST_SRCS))))
SRCS = $(shell find $(SRC) ! -name Main.cpp -name "*.cpp")
TEST_OBJS += $(subst $(SRC)/,$(BUILD)/,$(addsuffix .o,$(basename $(SRCS))))


# Build and run

runtest: build_test
	@echo "Executing Test ..."
	./$(TARGET_TEST) 

# Build task
build: $(TARGET)
build_test: $(TARGET_TEST)

# Task producing target from built files
$(TARGET): $(OBJS)
	@echo "Building target..."
	mkdir -p $(dir $@)
	ar rcs $@ $(OBJS)  
# $(CXX) $@ $(OBJS) 

# Compile all cpp files
$(BUILD)/%.o: $(SRC)/%.cpp
	@echo $(TEST_SRCS)
	@echo $(TEST_OBJS)
	mkdir -p $(dir $@)
	$(CXX) $(CXX_FLAGS) $(PRE_FLAGS) $(INC_FLAGS) -c -o $@ $< 

test: $(TARGET_TEST)

$(TARGET_TEST) : $(TEST_OBJS)
	@echo "Building test..."
	mkdir -p $(dir $@)
	$(CXX) $(TEST_OBJS) -o $@ $(LDFLAGS)

# Compile all cpp files
$(BUILD)/%.o: $(TEST_SRC)/%.cpp
	@echo $(TEST_SRCS)
	@echo $(TEST_OBJS)
	mkdir -p $(dir $@)
	$(CXX) $(CXX_FLAGS) $(PRE_FLAGS) $(INC_FLAGS) -c -o $@ $< 

# Clean task
.PHONY: clean
clean:
	@echo "Clearing..."
	rm -rf build
	rm -rf bin
	rm -rf $(SRC)/*.o
	rm -rf $(TEST_SRC)/*.o
