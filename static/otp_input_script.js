function OTPInput() {
  const inputs = document.querySelectorAll('#otp input[type="text"]');
  for (let i = 0; i < inputs.length; i++) { //count controlled loop -- increment

    inputs[i].addEventListener('keydown', function(event) {
      if (event.key === "Backspace") {
        inputs[i].value = '';
        if (i > 0){inputs[i - 1].focus()}; // go back to the last box
        event.preventDefault()
        }
      else if (/\d/.test(event.key)) { // Only numbers allowed
          if (i < inputs.length) {  
            inputs[i].value = event.key
            inputs[i + 1].focus();
            event.preventDefault()
          }
      else if (event.key === "Enter"){
        if (i === inputs.length-1 ){
          document.getElementById("form").submit()
        }
      }
      } else {
        event.preventDefault()
        }
      });

    inputs[i].addEventListener('paste', function(event){
      event.preventDefault()
      const paste = (event.clipboardData || window.clipboardData).getData('text');
      const numbers = paste.match(/\d/g) || [];
      numbers.slice(0, 6).forEach((num, j) => {
      if (inputs[j]) {
          inputs[j].value = num;
          if (j === numbers.length - 1) inputs[j].focus();}
        });
      });
    };
}
OTPInput();