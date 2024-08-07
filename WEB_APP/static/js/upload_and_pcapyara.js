document.addEventListener("DOMContentLoaded", function() {
    document.getElementById('uploadYaraPcapForm').addEventListener('submit', function (event) {
        event.preventDefault();

        var fileInput = document.getElementById('pcapFile');
        var file = fileInput.files[0];

        var formData = new FormData();
        formData.append('file', file);

        // Show the progress bar container
        document.getElementById("progressContainer").style.display = "block";

        fetch('/process_yara_pcap', {
            method: 'POST',
            body: formData
        })
        .then(response => response.text())
        .then(result => {
            // Hide the progress bar container
            // document.getElementById("progressContainer").style.display = "none";
            
            // Update the result container with the received result
            document.getElementById('resultsContainer').innerHTML = result;
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });
});
