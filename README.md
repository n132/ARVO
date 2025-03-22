# ARVO

ARVO: an Atlas of Reproducible Vulnerabilities in
Open source software.


By sourcing vulnerabilities from C/C++ projects that Google’s OSS-Fuzz discovered and
implementing a reliable re-compilation system, we successfully reproduce more than 5,000 memory vulnerabilities across over 250 projects (May 2024), each with a triggering input, the canonical developer-written patch for fixing the vulnerability, and the ability to automatically rebuild the project from source and run it at its vulnerable and patched revisions. Moreover, our dataset can be automatically updated as OSS-Fuzz finds new vulnerabilities, allowing it to grow over time. We provide a thorough characterization of the ARVO dataset, and show that it can locate fixes more accurately than Google’s own OSV reproduction effort.

# Docker Hub Interface
```shell
# Reproduce Vul/Fix
docker run --rm -it n132/arvo:25402-vul arvo
docker run --rm -it n132/arvo:25402-fix arvo
# Re-compile Vul/Fix
docker run --rm -it n132/arvo:25402-vul arvo compile 
docker run --rm -it n132/arvo:25402-fix arvo compile
```


# Reports

All ARVO-generated reports are in [this][2] directory. 
- [ ] Fix the broken URL for non-common repo


# Compiled Database

To maximize user convenience and efficiency, ARVO provides pre-compiled cases, each compressed into a Docker image that can be easily downloaded from the Internet. This approach ensures that users can access and utilize these cases with minimal effort and technical overhead.

The process of accessing and using these Docker images is designed to be straightforward, involving just three simple commands.
The source code and prepared re-compile environment are provided in the docker image to support custom modification.

```shell
localId=25402
tag=vul
cmd=arvo
docker run --rm -it n132/arvo:$localId-$tag $cmd
```
To compile, replace the original command `arvo` with `arvo compile`.

- $localId: any number of the reported issues. Get them from the function `getReports` or check the `reports` directory.
- $tag: "vul" or "fix"
- $command: "arvo" or "arvo compile"

# Rebuild the Database (optional)

- Run ARVO on Linux/Unix OS
- Install gcloud and required Python modules
- Clone ARVO from Github
- Create and config `_profile.py`, there is an example for your [referrence][3]
- Create the directory for ARVO
- Ready to run ARVO

# Warning

The following interface may fail if you don't finish the previous section.

# CLI Interface

```
[+] Usage:
[+]      python3 cli.py [Command] [LocalId]
[+]      Command: <reproduce, report>
[+]      LocalId: a number identifier for the issue in OSS-Fuzz
```

# Benchmark Interface


You can also use the API functions `cli_getMeta` and `cli_tryFIx`, or the script to interact with ARVO.
For `tryFix`, we now only support one-function-related fixes.

## getMeta

```py
python3 ./BenchmarkCLI.py getMeta <localId>
```

## tryFix

```py
python3 ./BenchmarkCLI.py getMeta <localId> <FixFile>
```



[1]: https://github.com/google/oss-fuzz/tree/master/projects
[2]: ./Reports
[3]: ./Setting.md
