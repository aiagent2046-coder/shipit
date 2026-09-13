const worker = new Worker('./harness-worker.js', { type: 'module' });
worker.onmessage = ({ data }) => {
  if (data.type === 'progress') document.querySelector('#status').textContent = data.message;
  else {
    document.querySelector('#status').textContent = data.summary?.unexpected_failures === 0 ? 'PASSED' : 'FAILED';
    document.querySelector('#result').textContent = JSON.stringify(data, null, 2);
    worker.terminate();
  }
};
worker.onerror = () => { document.querySelector('#status').textContent = 'FAILED: worker startup'; worker.terminate(); };
worker.postMessage({ type: 'run' });
