import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class ToastService {
  // The constructor runs exactly once when the application starts
  constructor() {
    this.createToastContainer();
  }

  private createToastContainer() {
    // 1. Check if the container already exists
    if (!document.getElementById('toast-container')) {
      // 2. Create the raw HTML <div> element in memory
      const container = document.createElement('div');
      container.id = 'toast-container';
      
      // 3. Add DaisyUI positioning classes (bottom right)
      // Note: Added z-50 to ensure it always floats above everything else
      container.className = 'toast toast-bottom toast-end'; 
      
      // 4. Attach it physically to the browser's <body> tag
      document.body.appendChild(container);
    }
  }

  // This will be called by our public methods (success, error, etc.) in the next lesson
  private createToastElement(message: string, alertClass: string, duration = 5000) {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) return;

    // 1. Create the alert box
    const toast = document.createElement('div');
    toast.classList.add('alert', alertClass, 'shadow-lg');

    // 2. Inject the HTML string (Using Template Literals/Backticks)
    toast.innerHTML = `
      <span>${message}</span>
      <button class="ml-4 btn btn-sm btn-ghost">x</button>
    `;

    // 3. Find the button we just created and add a click listener to it
    const button = toast.querySelector('button');
    button?.addEventListener('click', () => {
      // Check if it's still in the DOM before removing to prevent errors
      if (toastContainer.contains(toast)) {
        toastContainer.removeChild(toast);
      }
    });

    // 4. Show the toast on the screen
    toastContainer.appendChild(toast);

    // 5. Auto-remove the toast after the duration (5000ms = 5 seconds)
    setTimeout(() => {
      if (toastContainer.contains(toast)) {
        toastContainer.removeChild(toast);
      }
    }, duration);
  }
  // --- PUBLIC METHODS ---

  success(message: string, duration?: number) {
    this.createToastElement(message, 'alert-success', duration);
  }

  error(message: string, duration?:number) {
    this.createToastElement(message, 'alert-error', duration);
  }

  warning(message: string, duration?:number) {
    this.createToastElement(message, 'alert-warning', duration);
  }

  info(message: string, duration?:number) {
    this.createToastElement(message, 'alert-info', duration);
  }
}
