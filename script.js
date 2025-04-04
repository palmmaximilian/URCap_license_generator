document.getElementById('licenseForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const licenseType = document.getElementById('licenseType').value;
    const serialNumber = document.getElementById('serialNumber').value;
    
    // Your "secrets" - in a real app, these might come from a more secure source
    const secrets = {
        type1: "SECRET_ABC123",
        type2: "SECRET_DEF456"
    };
    
    const selectedSecret = secrets[licenseType] || "No secret found";
    
    // Display the output
    const outputDiv = document.getElementById('output');
    outputDiv.innerHTML = `
        <h3>Generation Result:</h3>
        <p><strong>License Type:</strong> ${licenseType}</p>
        <p><strong>Serial Number:</strong> ${serialNumber}</p>
        <p><strong>Secret:</strong> ${selectedSecret}</p>
    `;
});