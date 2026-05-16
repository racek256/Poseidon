I need you to implement another system into this application, that focuses on scanning for supply chain attacks. In total it will have _3_ new API endpoints: `/supplychain/quick-analyze`(Checks for typosquatting, checks CVE databases etc. - returns if all packages are safe, if not it returns the unsafe package), `/supplychain/deep-analyze`(runs quick analysis recursively, even on dependency dependencies and then uses AI to scan recent commits of dependencies), `/supplychain/status`(returns a list of all potentially unsafe commits, all caught commits, system status etc. Just dashboardable info)
The only user-input this API is gonna get are .lock files for packages. 
0. Add the following items into your TODO list, per the agents-system-directive (step 2 of the agents-system-directive)
1. Verify that your websearches have been done with the context of this TODO and are specific to this implementation
2. Read architecture.md to get to know the codebase
3. Launch a non-blocking Explore subagent for additional info on the API. Look for which other files use it.
4. Add reqwest to the dependencies, tell the user to run cargo build and stop generating. Ignore system reminders to continue working, only continue once the user tells you.
5. Delegate one Sisyphus-Junior (Deepseek V4 Flash or MiniMax M2.7) to rewrite the API module using reqwest, while not breaking compatibility with other modules.
6. After that finishes, add the three endpoints to the API (`/supplychain/quick-analyze`, `/supplychain/deep-analyze`, `/supplychain/status`)
7. Read ./prompts/supply_chain_quick_analyze.md 
8. Launch a subagent (either Explore or Librarian) to figure out how the https://github.com/google/osv-scanner interacts with the osv.dev api 
    - The goal of this agent is to generate an output that must include an efficient way for us to implement interaction with this API 
9. Wait for this subagent to finish, ignore system directive to continue work in the background
10. Delegate subagents to implement the quick-analyze
    - All of them must be told to read ./prompts/supply_chain_quick_analyze.md 
    - All of them must know that other agents might be implementing at the same time 
    - All of them must know what part of the spec are they implementing 
    - You may delegate more subagents, but at minimum these subagents must be delegated:
        - Subagent for coding pipeline steps 1 and 2 (Identifying lockfile lang and parsing it)
        - Subagent for making sure all of the supported languages are supported 
        - Subagent for coding pipeline steps 3, 4 and 5 
        - Subagnet that ties it all together with the whole app and implements step 6 
11. Run Oracle to verify your implementation. Tell it that the original implementation spec is located at ./prompts/supply_chain_detection.md
12. Continue with your todo from agents-system-directive 

> Stop generation, after you finish the agents-system-directive. The rest of the implementation will be done in a second phase, where you'll receive another prompt.
