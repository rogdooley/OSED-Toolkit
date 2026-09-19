# Visual Studio Notes

Use CMake generation to produce Visual Studio solutions:

Modern CMake 3.13+:

```bat
cd ..
cmake -G "Visual Studio 15 2017" -A Win32 -S . -B build_vs_easy -DLAB_PROFILE=easy -DHELPER_ASLR=OFF
cmake --build build_vs_easy --config Release
```

Legacy CMake 3.12:

```bat
cd ..
if not exist build_vs_easy mkdir build_vs_easy
pushd build_vs_easy
cmake -G "Visual Studio 15 2017" -A Win32 -DLAB_PROFILE=easy -DHELPER_ASLR=OFF ..
cmake --build . --config Release
popd
```

This keeps one authoritative build definition in `CMakeLists.txt`.
