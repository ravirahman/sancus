import { createMuiTheme } from '@material-ui/core/styles';

const theme = createMuiTheme({
  typography: {
    fontFamily: [
      'Roboto',
      'sans-serif',
    ].join(','),
  },
  palette: {
    primary: {
      main: '#D3D3D3',
    },
    secondary: {
      main: '#FF8E53',
    },
    error: {
      main: '#FF1744',
    },
    background: {
      default: '#f4f4f4',
    },
  },
});

export default theme;
