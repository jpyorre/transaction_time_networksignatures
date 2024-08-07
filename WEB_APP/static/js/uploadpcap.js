document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("submitButton").addEventListener("click", function (event) {
        event.preventDefault();

        // Hide the submit button and show the progress container
        this.style.display = "none";
        document.getElementById("progressContainer").style.display = "block";

        // Create a FormData object from the form
        var formData = new FormData(document.getElementById("uploadForm"));

        // Send the form data via AJAX
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/analyze_pcap", true);  // Make sure this is POST

        xhr.onload = function () {
            if (xhr.status === 200) {
                // Parse and display the results
                var results = JSON.parse(xhr.responseText);
                displayResults(results);
                // Stop polling as the operation is complete
                clearInterval(interval);
            } else {
                alert("An error occurred while uploading the file.");
            }
            // Show the submit button and hide the progress container
            document.getElementById("submitButton").style.display = "block";
            document.getElementById("progressContainer").style.display = "none";
            document.getElementById("progressBar").style.width = "0%";
            document.getElementById("progressBar").innerText = "";
        };
        xhr.send(formData);

        // Poll for progress
        var interval = setInterval(function () {
            var xhrProgress = new XMLHttpRequest();
            xhrProgress.open("GET", "/progress", true);
            xhrProgress.onload = function () {
                if (xhrProgress.status === 200) {
                    var progressData = JSON.parse(xhrProgress.responseText);
                    var progress = progressData.progress;
                    document.getElementById("progressBar").style.width = progress + "%";
                    document.getElementById("progressBar").innerText = progress + "%";

                    // Stop polling when progress reaches 100%
                    if (progress >= 100) {
                        clearInterval(interval);
                    }
                } else if (xhrProgress.status === 403) {
                    // Stop polling if the server returns 403 Forbidden
                    clearInterval(interval);
                    alert("Operation forbidden. Stopping progress updates.");
                } else if (xhrProgress.status === 404) {
                    // Stop polling if the server returns 404 Not Found
                    clearInterval(interval);
                    alert("Progress file not found. Stopping progress updates.");
                }
            };
            xhrProgress.onerror = function () {
                // Stop polling on any other error
                clearInterval(interval);
                alert("An error occurred while updating progress.");
            };
            xhrProgress.send();
        }, 1000);
    });
});

function displayResults(results) {
    var resultsContainer = document.getElementById("resultsContainer");
    resultsContainer.innerHTML = "";
    
    if (!results.matches || results.matches.length === 0) {
        resultsContainer.innerHTML = "<p>No matches found.</p>";
    } else {
        // Sort matches by ratio from highest to lowest
        results.matches.sort((a, b) => b.ratio - a.ratio);

        var ulWithMatches = document.createElement("ul");
        var MatchText = `
            <p><b>Matches:</b></p>
        `;
        results.matches.forEach(function (match) {
            var li = document.createElement("li");
            // Extract the filename from the full path
            var filename = match.filename.split('/').pop();
            li.innerHTML = `
                <strong>File:</strong> <a href="${match.filename}" target="_blank">${filename}</a><br>
                <strong>Signature Name:</strong> ${match.signature_name}<br>
                <strong>Ratio:</strong> ${match.ratio}%<br>
                <strong>Levenshtein Distance:</strong> ${match.levenshtein_distance}<br>
                <strong>Signature Percentages:</strong> ${match.signature_percentages}<br>
                
            `;
            ulWithMatches.appendChild(li);
        });
        resultsContainer.innerHTML += MatchText;
        resultsContainer.appendChild(ulWithMatches);
    }

    if (!results.unmatched || results.unmatched.length === 0) {
        resultsContainer.innerHTML += "<p>No unmatched files.</p>";
    } else {
        // Sort unmatched by ratio from highest to lowest
        results.unmatched.sort((a, b) => b.ratio - a.ratio);

        var ulNoMatches = document.createElement("ul");
        var noMatchText = `
            <p><b>No matches on any of the following flows:</b></p>
        `;
        results.unmatched.forEach(function (unmatch) {
            var li = document.createElement("li");
            // Extract the filename from the full path
            var filename = unmatch.filename.split('/').pop();
            li.innerHTML = `
                <a href="${unmatch.filename}" target="_blank">${filename}</a>: Ratio: ${unmatch.ratio}%<br>
                <strong>Levenshtein Distance:</strong> ${unmatch.levenshtein_distance}
            `;
            ulNoMatches.appendChild(li);
        });
        resultsContainer.innerHTML += noMatchText;
        resultsContainer.appendChild(ulNoMatches);
    }

    if (results.map_data) {
        displayMap(results.map_data);
    }
}
function displayMap(mapData) {
    var map = L.map('map').setView([0, 0], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 18,
    }).addTo(map);

    var srcIcon = L.icon({
        iconUrl: 'static/css/images/blackskull.png',  // Path to your custom icon for unmapped IPs
        iconSize: [30, 30],  // Size of the icon
        iconAnchor: [12, 41],  // Point of the icon which will correspond to marker's location
        popupAnchor: [1, -34],  // Point from which the popup should open relative to the iconAnchor
    });

    var dstIcon = L.icon({
        iconUrl: 'static/css/images/redskull.png',  // Path to your custom icon for unmapped IPs
        iconSize: [30, 30],  // Size of the icon
        iconAnchor: [12, 41],  // Point of the icon which will correspond to marker's location
        popupAnchor: [1, -34],  // Point from which the popup should open relative to the iconAnchor
    });

    mapData.src.forEach(function (location) {
        // L.marker([location.lat, location.lon])
        L.marker([location.lat, location.lon], { icon: srcIcon })
            .bindPopup(location.description)
            .addTo(map);
    });

    mapData.dst.forEach(function (location) {
        // L.marker([location.lat, location.lon])
        L.marker([location.lat, location.lon], { icon: dstIcon })
            .bindPopup(location.description)
            .addTo(map);
    });

    // mapData.unmapped.forEach(function (ip) {
    //     L.marker([0, 0], { icon: srcIcon })
    //         .bindPopup(`unmapped IP: ${ip}`)
    //         .addTo(map);
    // });
}

