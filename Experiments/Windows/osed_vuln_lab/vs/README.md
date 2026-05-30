# Visual Studio Notes

Use CMake generation to produce Visual Studio solutions:

```bat
cmake -S .. -B ..\build_vs_easy -G "Visual Studio 17 2022" -A Win32 -DLAB_PROFILE=easy -DHELPER_ASLR=OFF
```

This keeps one authoritative build definition in `CMakeLists.txt`.
