// A pretend AI for end-to-end tests: no account, no cost. It reads the prompt and always gives the same answer.
let prompt = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (prompt += chunk));
process.stdin.on("end", () => {
  const isReview = prompt.includes("<proposal>");
  console.log(isReview ? JSON.stringify({ verdict: "agree" }) : JSON.stringify({ name: "ci_placeholder", summary: "Placeholder answer from the test AI.", confidence: "high" }));
});
