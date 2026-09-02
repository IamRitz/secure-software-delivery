import { createApp } from './app.js';

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const app = createApp();

app.listen(port, (error) => {
  if (error) {
    console.error(`failed to listen on port ${port}: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  console.log(`secure-software-delivery listening on port ${port}`);
});
