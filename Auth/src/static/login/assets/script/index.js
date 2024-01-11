function login() {
  const form = document.getElementById("login-form");
  // form.addEventListener("submit", (e) => e.preventDefault());

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
  // const apiUrl = 'http://localhost:8000/auth/passwordflow/token';
  const apiUrl = "http://localhost:3000/api/v1/auth/login";

  // Options for the fetch request
  const requestOptions = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded", // Set the content type to Form
      // You may include additional headers if needed
    },
    body: postData.toString(), // Convert the data to JSON format
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
      console.log(data);
      console.log("POST request (login) successful:");
      // TODO: Store access_token and refresh_token in sameSite HttpOnly Cookie
      // and set Authorization header
      const secureCookie = false; // set true for https only request
      //   const cookieOptions = `Secure=${secureCookie}; HttpOnly=true; SameSite=Lax`;
      const cookieOptions = `Secure=${secureCookie}; SameSite=Lax;`;

      document.cookie = `access_token=${data.accessToken}; ${cookieOptions}`;
      document.cookie = `refresh_token=${data.refreshToken}; ${cookieOptions}`;
      console.log(document.cookie); // will show all cookies

      const authorizationHeader = `Bearer ${data.access_token}`;
      // const requestOptions = {
      //   method: 'GET',
      //   headers: {
      //     'Authorization': authorizationHeader,
      //   },
      // };

      const currentUrl = window.location.href;
      const urlSearchParams = new URLSearchParams(new URL(currentUrl).search);
      const redirect_uri = urlSearchParams.get("redirect_uri");
      //   console.log(redirect_uri);
      //   window.location.href = redirect_uri;
    })
    .catch((error) => {
      console.error("Error making POST request:", error);
      // Handle errors
      // TODO: Display Error on login page
      const errorDiv = document.getElementById("error-message");
      errorDiv.innerHTML = error;
    });
}
