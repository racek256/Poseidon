> Note: If you're readig this, you're most likely a subagent
> For subagents: Follow the agents-system-directive, when implementing your part of the spec, unless you're a GLM model, then this directive doesn't apply to you. MiniMax, Deepseek and other models still have to follow this directive.
# Quick Analysis implementation specification
This module needs to support these languages and their lockfiles:
* Rust (Cargo, `Cargo.lock`)
* JavaScript / TypeScript (npm, `package-lock.json`)
* JavaScript / TypeScript (Yarn, `yarn.lock`)
* JavaScript / TypeScript (pnpm, `pnpm-lock.yaml`)
* Python (Poetry, `poetry.lock`)
* Python (Pipenv, `Pipfile.lock`)
* Python (pip-tools, `requirements.txt`)
* Go (Go Modules, `go.sum`)
* Ruby (Bundler, `Gemfile.lock`)
* PHP (Composer, `composer.lock`)
* Java / Kotlin / Scala (Maven, `pom.xml` / `maven-lockfile.json`)
* Java / Kotlin / Scala (Gradle, `gradle.lockfile`)
* .NET / C# / F# (NuGet, `packages.lock.json`)
* Dart / Flutter (Pub, `pubspec.lock`)
* Elixir (Mix, `mix.lock`)

The quick analysis module will most likely be ran using GitHub actions or alternatives, so the api endpoint must account for that.
When running quick analysis, the output must always be one lockfile of dependencies, this file will then go through this pipeline:
1. Figure out which language's lockfile did the API just get. Matching based on name will be the most effective. (Cargo.lock -> Rust etc.)
2. Extracts each package with it's version and puts them into a list of some kind - dictionary. Choose any datatype that you find suitable 
> Each of the steps below are done for each package 
3. It checks the package against the OSV api (your main agent should've given you implementation info)
4. It checks the pacakge metadata on it's registry(PyPI, npm...)
    - It looks for how old it is -> packages younger than a week are a severe warning
    - It checks if the owner has been recently changed -> recent owner changes should be flagged as a severe warning 
    - It looks if this specific version number has not been yanked from the registry -> if yes it indicates a security issue and should be rejected immediately
5. It checks for typosquatting based on a list of commonly used packages 
> End of steps ran for each package 
6. It returns a JSON of every package and it's warning level, along with one field containing an overall sentiment - this sentiment is based on the highest warning level a package in the lockfile got 

