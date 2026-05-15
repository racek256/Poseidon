I need you to make an interactive TUI for this project. It doesn't need to be anything pretty, but it needs to do one thing, present as much info as possible on an organised screen, since it's gonna be used for testing.
You must:
0. Add the following items into your TODO
1. Read architecture.md to get a hang of the codebase
2. Implement a new flag that can be passed into the command line to activate interactive mode (the TUI)
3. Build a good looking TUI baseline using ratatui. The basic things it must contain are:
    - An input prompt
    - Generation speed statistics under the input prompt
    - A "currently working on" indicator, that says what step is currently being processed (The tracking for this will be added in the next step, keep it a placeholder for now)
    - A bar on the right containing more statistics (You may put placeholders in there for now, real statistics are going to get filled in the next step)
    - A window containing server logs 
    - A window containing whether the output 
5. Make the server post it's current step of generating and it's progress to the TUI 
6. Add trackers for speed, delay and performance analysis, that only run when the interactive mode is turned on 
7. Make these trackers display on the right side bar in the TUI 
8. Consult Oracle to check for potential issues. Make sure to tell it to read ./prompts/TUI.md, so it can check whether the Implementation is according to the spec 
9. Output "meow :3" once finished.

--- 

Make sure to **use subagents**, it is very important that you do not write all of the code alone. You may write some of the code, when fixing things and cleaning up their work, but it is very inefficient, if you write most of it. 

---

Additional TUI implementation info:
 - the TUI background color should be: #0f0f0f
 - the highlight color should be: #3365e6 
 - Other colors should also be used, to prevent the TUI from looking bland

Additional info for agents:
 - **Ignore** TUI_tracking_things.txt
