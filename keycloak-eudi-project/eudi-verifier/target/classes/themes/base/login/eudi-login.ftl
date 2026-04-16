<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        Autentificare cu EUDI Wallet
    <#elseif section = "form">
        <div style="text-align: center; padding: 20px;">
            <h2 style="margin-bottom: 20px;">Scanează QR Code cu Lissi Wallet</h2>
            
            <div class="alert alert-info" style="margin-bottom: 20px;">
                <p><strong>Instrucțiuni:</strong></p>
                <ol style="text-align: left; display: inline-block;">
                    <li>Deschide aplicația <strong>Lissi Wallet</strong> pe telefon</li>
                    <li>Apasă pe butonul de <strong>scanare QR</strong></li>
                    <li>Scanează codul QR de mai jos</li>
                    <li>Selectează credențialele PID și confirmă partajarea</li>
                </ol>
            </div>
            
            <!-- QR Code Container -->
            <div id="qr-code" style="display: inline-block; padding: 20px; background: white; border: 2px solid #ccc; border-radius: 10px; margin: 20px 0;"></div>
            
            <!-- Loading indicator -->
            <div id="loading-indicator" style="display: none; margin-top: 20px;">
                <p>⏳ Așteptăm confirmarea din wallet...</p>
                <div class="spinner" style="border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto;"></div>
            </div>
            
            <!-- Success message -->
            <div id="success-message" style="display: none; margin-top: 20px; color: green;">
                <p>✅ Autentificare reușită! Redirecționare...</p>
            </div>
            
            <!-- Debug info (doar pentru development) -->
            <details style="margin-top: 30px; text-align: left; max-width: 600px; margin-left: auto; margin-right: auto;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Debug Info (pentru development)</summary>
                <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin-top: 10px; font-family: monospace; font-size: 12px;">
                    <p><strong>Callback URL:</strong><br/>${callbackUrl!""}</p>
                    <p><strong>State:</strong> ${state!""}</p>
                    <p style="word-break: break-all;"><strong>Authorization Request (primele 200 chars):</strong><br/>${authRequestUrl?substring(0, 200)!""}...</p>
                </div>
            </details>
        </div>

        <!-- Include QRCode.js library -->
        <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
        
        <style>
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
        
        <script>
            (function() {
                // Generează QR Code cu Authorization Request URL
                const authRequestUrl = "${authRequestUrl?js_string}";
                const state = "${state?js_string}";
                const callbackUrl = "${callbackUrl?js_string}";
                
                console.log("=== EUDI Verifier Debug Info ===");
                console.log("Auth Request URL:", authRequestUrl);
                console.log("State:", state);
                console.log("Callback URL:", callbackUrl);
                
                // Generează QR code
                try {
                    new QRCode(document.getElementById("qr-code"), {
                        text: authRequestUrl,
                        width: 300,
                        height: 300,
                        colorDark: "#000000",
                        colorLight: "#ffffff",
                        correctLevel: QRCode.CorrectLevel.M
                    });
                    
                    console.log("✅ QR Code generated successfully");
                    
                    // Afișează loading indicator după generarea QR-ului
                    setTimeout(() => {
                        document.getElementById("loading-indicator").style.display = "block";
                    }, 500);
                    
                } catch (error) {
                    console.error("❌ Error generating QR code:", error);
                    alert("Eroare la generarea QR code-ului: " + error.message);
                }
                
                // Polling pentru verificarea autentificării
                let pollAttempts = 0;
                const maxPollAttempts = 60; // 60 * 5 secunde = 5 minute
                
                const pollInterval = setInterval(async () => {
                    pollAttempts++;
                    
                    console.log(`Polling attempt ${pollAttempts}/${maxPollAttempts} - checking authentication status...`);
                    
                    if (pollAttempts >= maxPollAttempts) {
                        clearInterval(pollInterval);
                        console.log("❌ Polling timeout - no authentication received");
                        alert("Timeout: Nu s-a primit autentificare în timp util. Încearcă din nou.");
                        return;
                    }
                    
                    try {
                        const statusUrl = callbackUrl.replace('/callback', '/status') + '?state=' + encodeURIComponent(state);
                        console.log("Checking status at:", statusUrl);
                        
                        const response = await fetch(statusUrl, {
                            method: 'GET',
                            headers: {
                                'Accept': 'application/json'
                            }
                        });
                        
                        if (response.ok) {
                            const data = await response.json();
                            console.log("Status response:", data);
                            
                            if (data.authenticated === true) {
                                console.log("✅ Authentication successful!");
                                clearInterval(pollInterval);
                                
                                // Afișează success message
                                document.getElementById("loading-indicator").style.display = "none";
                                document.getElementById("success-message").style.display = "block";
                                
                                // Reîncarcă pagina pentru a finaliza autentificarea în Keycloak
                                setTimeout(() => {
                                    console.log("Reloading page to complete authentication...");
                                    window.location.reload();
                                }, 2000);
                            }
                        } else {
                            console.log("Status check returned non-OK status:", response.status);
                        }
                        
                    } catch (error) {
                        console.error("Error during polling:", error);
                        // Nu oprim polling-ul la erori temporare
                    }
                    
                }, 5000); // Poll la fiecare 5 secunde
                
                // Cleanup la unload
                window.addEventListener('beforeunload', () => {
                    clearInterval(pollInterval);
                });
                
            })();
        </script>
    </#if>
</@layout.registrationLayout>