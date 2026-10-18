// A pretend AI for testing the pipeline without spending any AI quota or needing a login.
// It reads the prompt and always answers the same thing. Use with: REA_POOL_AI="node examples/fake-ai.ts"
process.stdin.resume();
process.stdin.on("end", () => {
  console.log(JSON.stringify({ name: "placeholder_function", summary: "Placeholder answer from the pretend AI.", confidence: "low" }));
});
