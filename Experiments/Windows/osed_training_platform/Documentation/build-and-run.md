# Build And Run

## Visual Studio / CMake

From a Developer Command Prompt for Visual Studio:

```bat
cd Experiments\Windows\osed_training_platform
cmake -S . -B build -A Win32 -DTRAINING_PROFILE=analysis
cmake --build build --config Release
```

For later mitigation-focused builds:

```bat
cmake -S . -B build_dep -A Win32 -DTRAINING_PROFILE=dep
cmake --build build_dep --config Release

cmake -S . -B build_aslr_dep -A Win32 -DTRAINING_PROFILE=aslr_dep
cmake --build build_aslr_dep --config Release
```

## Run

Start the service:

```bat
osedtp_service.exe
```

Send a benign request:

```bat
osedtp_client.exe --mode hello --name student
```

Authorization and diagnostic modes are also safe to run:

```bat
osedtp_client.exe --mode auth --name student --token 0xC0FFEE11
osedtp_client.exe --mode diag --name student --command audit --diag "baseline check"
```
