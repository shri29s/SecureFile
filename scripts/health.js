const response = await fetch(`http://127.0.0.1:${process.env.PORT || 3001}/health`);
console.log(await response.json());
if (!response.ok) process.exitCode = 1;
