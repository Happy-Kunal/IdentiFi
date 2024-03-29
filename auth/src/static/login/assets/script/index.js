function login() {
  const form = document.getElementById("login-form");

  const formData = new FormData(form);

  // Example data to be sent in the POST request
  const postData = new URLSearchParams();
  postData.append("grant_type", "password");
  postData.append("username", formData.get("username"));
  postData.append("password", formData.get("password"));
  postData.append("scope", "principal-user:worker");
  postData.append("client_id", formData.get("client-id"));
  console.log(postData.toString());

  // URL to which the POST request will be sent
  const apiUrl = 'http://api.localhost/auth/passwordflow/token';

  // Options for the fetch request
  const requestOptions = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded", // Set the content type to Form
      // You may include additional headers if needed
    },
    body: postData.toString(), // Convert the data to JSON format
    credentials: 'same-origin',
  };

  // Make the POST request using fetch
  fetch(apiUrl, requestOptions)
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return response.json(); // Parse the JSON response
    })
    .then((data) => {
      console.log("POST request (login) successful:");

      const currentUrl = window.location.href;
      const urlSearchParams = new URLSearchParams(new URL(currentUrl).search);
      const redirect_uri = urlSearchParams.get("redirect_uri");

      window.location.href = redirect_uri;
    })
    .catch((error) => {
      console.error("Error making POST request:", error);
      const errorDiv = document.getElementById("error-message");
      errorDiv.innerHTML = error;
    });
}
