# Visual Studio Notes

Use CMake generation to produce Visual Studio solutions:

Use a generator reported by `cmake --help`; no Visual Studio release is
assumed. The commands below let CMake select its default installed generator.

Modern CMake 3.13+:

```bat
cd ..
cmake -A Win32 -S . -B build_easy -DLAB_PROFILE=easy -DHELPER_ASLR=OFF
cmake --build build_easy --config Release
```

Legacy CMake 3.12:

```bat
cd ..
if not exist build_easy mkdir build_easy
pushd build_easy
cmake -A Win32 -DLAB_PROFILE=easy -DHELPER_ASLR=OFF ..
cmake --build . --config Release
popd
```

This keeps one authoritative build definition in `CMakeLists.txt`.
