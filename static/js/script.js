document.addEventListener('DOMContentLoaded', () => {
    
    // Find the HTML element with the id 'timer'
    const timerElement = document.getElementById('timer');
    
    // Get the starting time from the element's text
    let timeLeft = parseInt(timerElement.textContent);

    // Run the countdown function every 1000 milliseconds (1 second)
    const timerId = setInterval(() => {
        timeLeft--;
        timerElement.textContent = timeLeft;

        // When the timer reaches 0
        if (timeLeft <= 0) {
            clearInterval(timerId); // Stop the timer
            alert("Time's up!"); // Show a popup message
            // Later, we will make this automatically submit the quiz
        }
    }, 1000);
});