import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { NavigationExtras, Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { ToastService } from '../services/toast-service';

export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const toast = inject(ToastService);

  // 'next(req)' sends the HTTP request on its way.
  // We use .pipe() to intercept the RESPONSE on its way back.
  return next(req).pipe(
    catchError((error) => {
      if (error) {
        switch (error.status) {
          case 400:
            if (error.error.errors) {
              const modelStateErrors = [];
              for (const key in error.error.errors) {
                if (error.error.errors[key]) {
                  modelStateErrors.push(error.error.errors[key]);
                }
              }
              // Flatten the 2D array into a 1D array of strings and throw it back to the component
              throw modelStateErrors.flat();
            } else {
              // Otherwise, it's a normal string error (like "Email already taken")
              toast.error(error.error);
            }
            break;
          case 401:
            toast.error('Unauthorized');
            break;
          case 404:
            router.navigateByUrl('/not-found');
            break;
          case 500:
            const navigationExtras: NavigationExtras = { state: { error: error.error } }
            router.navigateByUrl('/server-error',navigationExtras)
            break;
          default:
            toast.error('Something went wrong');
            break;
        }
      }

      // We must throw the error back to the component in case it wants to do something specific with it
      return throwError(() => error);
    }),
  );
};
