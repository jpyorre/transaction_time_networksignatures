var jsonData = JSON.parse(document.getElementById("json_data").textContent);

function createSignatureList(data) {
    var container = document.getElementById('current_signatures');
    container.innerHTML = '';

    if (Object.keys(data).length === 0) {
        container.innerHTML = '<p>No signatures yet</p>';
        return;
    }

    for (var signature in data) {
        if (data.hasOwnProperty(signature)) {
            var uniqueId = signature.replace(/[^a-zA-Z0-9]/g, '_'); // Ensure unique IDs
            
            var card = document.createElement('div');
            card.className = 'card';
            
            var cardHeader = document.createElement('div');
            cardHeader.className = 'card-header';
            cardHeader.id = 'heading' + uniqueId;
            
            var h2 = document.createElement('h2');
            h2.className = 'mb-0';
            
            var button = document.createElement('button');
            button.className = 'btn btn-link';
            button.type = 'button';
            button.setAttribute('data-toggle', 'collapse');
            button.setAttribute('data-target', '#collapse' + uniqueId);
            button.setAttribute('aria-expanded', 'true');
            button.setAttribute('aria-controls', 'collapse' + uniqueId);
            button.innerText = signature;
            
            h2.appendChild(button);
            cardHeader.appendChild(h2);
            card.appendChild(cardHeader);
            
            var collapseDiv = document.createElement('div');
            collapseDiv.id = 'collapse' + uniqueId;
            collapseDiv.className = 'collapse';
            collapseDiv.setAttribute('aria-labelledby', 'heading' + uniqueId);
            collapseDiv.setAttribute('data-parent', '#current_signatures');
            
            var cardBody = document.createElement('div');
            cardBody.className = 'card-body';

            if (Array.isArray(data[signature])) {
                cardBody.innerText = data[signature].join(', ');
            } else {
                cardBody.innerText = JSON.stringify(data[signature], null, 2);
            }
            
            collapseDiv.appendChild(cardBody);
            card.appendChild(collapseDiv);
            container.appendChild(card);
        }
    }
}

function handleUploadCompletion(updatedData, filename) {
    document.getElementById('signature_resultsContainer').style.display = 'block';
    document.getElementById('signature_resultsContainer').innerHTML = `<p>Added: ${filename}</p>`;
    createSignatureList(updatedData);
}

document.getElementById('uploadSignatureForm').addEventListener('submit', function(event) {
    event.preventDefault();
    
    var formData = new FormData(this);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', document.getElementById('uploadSignatureForm').action, true);
    
    xhr.onload = function() {
        if (xhr.status === 200) {
            var response = JSON.parse(xhr.responseText);
            handleUploadCompletion(response.updated_data, response.filename);
        } else {
            alert('An error occurred!');
        }
    };
    
    xhr.send(formData);
});

// event listener for delete button
document.getElementById('deleteAllSignaturesButton').addEventListener('click', function() {
    if (confirm('Are you sure you want to delete all signatures?')) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/delete_signatures', true);
        xhr.onload = function() {
            if (xhr.status === 200) {
                var response = JSON.parse(xhr.responseText);
                // alert(response.message);
                createSignatureList({});
            } else {
                alert('An error occurred while deleting signatures!');
            }
        };
        xhr.send();
    }
});

createSignatureList(jsonData);
