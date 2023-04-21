<?php
if($_SERVER["REQUEST_METHOD"] == "POST") {
  $name = strip_tags(trim($_POST["name"]));
  $email = filter_var(trim($_POST["email"]), FILTER_SANITIZE_EMAIL);
  $message = trim($_POST["message"]);

  if(empty($name) || empty($message) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo "Please complete the form and try again.";
    exit;
  }

  $to = "Null@email.com"; // replace with your email address
  $subject = "New contact form submission from $name";
  $email_body = "Name: $name\n";
  $email_body .= "Email: $email\n";
  $email_body .= "Message:\n$message\n";

  $headers = "From: $name <$email>";

  if(mail($to, $subject, $email_body, $headers)) {
    http_response_code(200);
    echo "Thank you for contacting us!";
  } else {
    http_response_code(500);
    echo "Oops! Something went wrong and we couldn't send your message.";
  }
} else {
  http_response_code(403);
  echo "There was a problem with your submission, please try again.";
}
?>
