Now we're going to move on onto the second phase of the implementation - implementing deep analysis and a status API.
> The first phase implementation steps can be found at ./prompts/supply_chain_detection.md 
> If you are on a new session and don't have current codebase context in your context follow first phase steps 1 through 3 

0. Make sure that you followed agents-system-directive, if yes, you may continue 
1. At the project root create a .env.example file containing three fields, one for "LLM_PROVIDER", one for "PROVIDER_API_KEY" and the last for "LLM_MODEL"
2. Delegate subagents to write another module called universal_llm_comms.rs that allows to call one function, that automatically requests a message to the agent on the provider, that are defined in .env. It takes one arg: prompt and returns the agent's output. It must support these providers:
    - OpenAI
    - Opencode ZEN
    - Opencode GO 
    - Local ollama models
    - Note: make sure to tell the subagents to research how the APIs of these providers work, before implementing.
3. Delegate subagents to write another module: get_dependency_git_url.rs - this does exactly what it sounds like:
    - It takes two things: package name and it's registry(npm, pypi etc.)
    - It then tries to find the package's git url on it's registry.
    - If it finds it, it returns it 
    - It must be compatible with the package registries for languages defined in ./prompts/supply_chain_quick_analyze.md 
4. Run Oracle on these modules to verify, that they're written properly and don't contain errors
5. Read ./prompts/supply_chain_deep_analysis.md to get context
6. Run Oracle again, this time with the goal of spotting parts of codes, that will need to be modified to implement the deep analysis. Give it the path for the implementation spec
7. Delegate subagents to code the deep analysis. Multiple agents will be required.
8. Write unittests for everything that has been made 
9. Run the new code through Oracle
