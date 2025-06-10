import { Component } from '@angular/core';
import { WebauthnService } from './webauthn.service';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-root',
  imports: [FormsModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'fido2client';

    username = '';

  
  constructor(private fidoService: WebauthnService) {}

  register() {
    this.fidoService.register(this.username).then(() => alert('Registriert!'));
  }

  login() {
    this.fidoService.authenticate(this.username).then(success => {
      alert(success ? 'Angemeldet!' : 'Fehlgeschlagen!');
    });
  }
  
}
