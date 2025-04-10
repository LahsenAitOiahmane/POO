// main.js

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initTooltips();
    
    // Add animation classes to elements when they come into view
    animateOnScroll();
    
    // Initialize scan form if it exists
    initScanForm();
    
    // Initialize results page interactivity if on results page
    if (document.querySelector('.results-container')) {
        initResultsPage();
    }
});

/**
 * Initialize Bootstrap tooltips
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Add animation when elements scroll into view
 */
function animateOnScroll() {
    const animatedElements = document.querySelectorAll('.card, .stat-card, .vulnerability-card');
    
    // Create an intersection observer
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            // If element is in view
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                // Unobserve after animation is added
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });
    
    // Observe each element
    animatedElements.forEach(el => {
        observer.observe(el);
    });
}

/**
 * Initialize scan form functionality
 */
function initScanForm() {
    const scanForm = document.getElementById('scan-form');
    if (!scanForm) return;
    
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Form validation
        const urlInput = document.getElementById('target-url');
        const urlValue = urlInput.value.trim();
        
        if (!isValidUrl(urlValue)) {
            showError(urlInput, 'Please enter a valid URL including http:// or https://');
            return;
        }
        
        // Clear any previous errors
        clearError(urlInput);
        
        // Show loading state
        document.getElementById('loading').classList.remove('d-none');
        document.querySelector('button[type="submit"]').disabled = true;
        
        // Display progress animation
        showScanProgress();
        
        // Submit the form via AJAX
        const formData = new FormData(this);
        
        fetch('/scan', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                // Show error message
                showToast('Error', data.error, 'danger');
                document.getElementById('loading').classList.add('d-none');
                document.querySelector('button[type="submit"]').disabled = false;
            } else if (data.redirect) {
                // Redirect to results page with animation
                document.querySelector('.card').classList.add('scale-in');
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 300);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('Error', 'An error occurred during the scan. Please try again.', 'danger');
            document.getElementById('loading').classList.add('d-none');
            document.querySelector('button[type="submit"]').disabled = false;
        });
    });
}

/**
 * Initialize results page interactivity
 */
function initResultsPage() {
    // Add filter functionality
    const filterButtons = document.querySelectorAll('[data-filter]');
    if (filterButtons.length > 0) {
        filterButtons.forEach(button => {
            button.addEventListener('click', function() {
                const filter = this.getAttribute('data-filter');
                
                // Remove active class from all buttons
                filterButtons.forEach(btn => btn.classList.remove('active'));
                
                // Add active class to clicked button
                this.classList.add('active');
                
                // Filter the vulnerabilities
                const vulnCards = document.querySelectorAll('.vulnerability-card');
                vulnCards.forEach(card => {
                    if (filter === 'all' || card.classList.contains(filter)) {
                        card.style.display = 'block';
                        setTimeout(() => {
                            card.style.opacity = '1';
                        }, 10);
                    } else {
                        card.style.opacity = '0';
                        setTimeout(() => {
                            card.style.display = 'none';
                        }, 300);
                    }
                });
            });
        });
    }
    
    // Add collapsible details functionality
    const detailsToggles = document.querySelectorAll('.details-toggle');
    detailsToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const detailsId = this.getAttribute('data-target');
            const details = document.getElementById(detailsId);
            
            if (details.classList.contains('show')) {
                details.style.maxHeight = '0';
                setTimeout(() => {
                    details.classList.remove('show');
                }, 300);
                this.innerHTML = 'Show Details <i class="fas fa-chevron-down"></i>';
            } else {
                details.classList.add('show');
                details.style.maxHeight = details.scrollHeight + 'px';
                this.innerHTML = 'Hide Details <i class="fas fa-chevron-up"></i>';
            }
        });
    });
}

/**
 * Show an animated progress bar for the scanning process
 */
function showScanProgress() {
    // Create progress container if it doesn't exist
    let progressContainer = document.getElementById('scan-progress');
    if (!progressContainer) {
        progressContainer = document.createElement('div');
        progressContainer.id = 'scan-progress';
        progressContainer.className = 'mt-4';
        
        const progressHTML = `
            <h6>Scanning Process:</h6>
            <div class="progress mb-3">
                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                     role="progressbar" style="width: 0%" id="crawl-progress">
                    Crawling
                </div>
            </div>
            <div class="progress mb-3">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-info" 
                     role="progressbar" style="width: 0%" id="scan-progress-bar">
                    Testing Vulnerabilities
                </div>
            </div>
            <div class="progress">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-success" 
                     role="progressbar" style="width: 0%" id="report-progress">
                    Generating Report
                </div>
            </div>
        `;
        
        progressContainer.innerHTML = progressHTML;
        document.getElementById('loading').after(progressContainer);
    }
    
    // Animate the progress bars
    setTimeout(() => {
        document.getElementById('crawl-progress').style.width = '100%';
    }, 500);
    
    setTimeout(() => {
        document.getElementById('scan-progress-bar').style.width = '80%';
    }, 2000);
    
    setTimeout(() => {
        document.getElementById('scan-progress-bar').style.width = '100%';
    }, 4000);
    
    setTimeout(() => {
        document.getElementById('report-progress').style.width = '100%';
    }, 5000);
}

/**
 * Validate URL format
 * @param {string} url - URL to validate
 * @returns {boolean} - True if valid URL
 */
function isValidUrl(url) {
    try {
        const parsedUrl = new URL(url);
        return ['http:', 'https:'].includes(parsedUrl.protocol);
    } catch (e) {
        return false;
    }
}

/**
 * Show input validation error
 * @param {HTMLElement} inputElement - Input element
 * @param {string} message - Error message
 */
function showError(inputElement, message) {
    clearError(inputElement);
    
    inputElement.classList.add('is-invalid');
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'invalid-feedback';
    errorDiv.textContent = message;
    
    inputElement.parentNode.appendChild(errorDiv);
}

/**
 * Clear input validation error
 * @param {HTMLElement} inputElement - Input element
 */
function clearError(inputElement) {
    inputElement.classList.remove('is-invalid');
    
    const existingError = inputElement.parentNode.querySelector('.invalid-feedback');
    if (existingError) {
        existingError.remove();
    }
}

/**
 * Show toast notification
 * @param {string} title - Toast title
 * @param {string} message - Toast message
 * @param {string} toast - Toast
 */
 