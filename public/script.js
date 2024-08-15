document.getElementById('urlForm').addEventListener('submit', async function (e) {
  e.preventDefault();

  const originalUrl = document.getElementById('originalUrl').value;
  const resultDiv = document.getElementById('result');

  // Clear previous result
  resultDiv.textContent = '';

  try {
    const response = await fetch('/shorten', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({originalUrl}),
    });

    // Log the raw response for inspection
    const textResponse = await response.text();
    console.log('Raw response:', textResponse);

    if (!response.ok) {
      throw new Error('Failed to shorten URL');
    }

    const data = await response.json();

    resultDiv.innerHTML = `Shortened URL: <a href="/${data.shortId}" target="_blank">${window.location.origin}/${data.shortId}</a>`;
  } catch (error) {
    resultDiv.textContent = `Error: ${error.message}`;
  }
});
