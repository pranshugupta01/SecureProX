// Add a listener to detect when a link is hovered
document.addEventListener("mouseover", function (event) {
    var target = event.target;
  
    // Check if the hovered element is a link
    if (target.tagName === "H3") {
      var websiteName = target.textContent;
      // Fetch website information here (e.g., using an API)
  
      // Create a temporary dialog box
      var dialogBox = document.createElement("div");
      dialogBox.style.position = "absolute";
      dialogBox.style.top = event.clientY + "px";
      dialogBox.style.left = event.clientX + "px";
      dialogBox.style.padding = "10px";
      dialogBox.style.backgroundColor = "white";
      dialogBox.style.border = "1px solid #ccc";
      dialogBox.style.zIndex = "9999";
  
      // Populate the dialog box with website information
      dialogBox.innerHTML = `
        <p>Name: ${websiteName}</p>
        <p><button className="btn btn-primary">button1</button></p>
        <p><button className="btn btn-primary">button2</button></p>
        <p><button className="btn btn-primary">button3</button></p>
      `;
  
      // Append the dialog box to the body
      document.body.appendChild(dialogBox);
  
      // Remove the dialog box when the mouse moves out of the link
      target.addEventListener("mouseout", function () {
        document.body.removeChild(dialogBox);
      });
    }
  });
  