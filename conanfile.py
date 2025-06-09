from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps

class MP3Conan(ConanFile):
  name = "MP3 Scraper"
  version = "1.0"
  settings = "os", "compiler", "build_type", "arch"

  def requirements(self):
    self.requires("libev/4.33")

  def generate(self):
    tc = CMakeToolchain(self)
    tc.generate()
    deps = CMakeDeps(self)
    deps.generate()

  def build(self):
    cmake = CMake(self)
    cmake.configure()
    cmake.build()
