// INERT scanner fixture. No code below executes.
if (false) {
  const external = "fixture";
  eval(external);
  new Function(external)();
  require("child_process").exec("echo fixture");
  fetch("https://example.invalid/fixture");
}
console.log("INERT scanner fixture");
