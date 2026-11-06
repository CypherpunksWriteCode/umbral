package org.umbral.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel

/**
 * One place for all network modules: DNS, Tor, I2P, Routing. Keeps the bottom
 * navigation small (5 tabs) while each module keeps its own screen.
 */
@Composable
fun NetScreen(vm: MainViewModel) {
    var tab by remember { mutableIntStateOf(0) }
    val titles = listOf("DNS", "Tor", "I2P", "Routing")

    Column(Modifier.fillMaxSize()) {
        Text(
            "Advanced settings",
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.padding(start = 16.dp, top = 12.dp)
        )
        ScrollableTabRow(selectedTabIndex = tab, edgePadding = 16.dp) {
            titles.forEachIndexed { i, title ->
                Tab(
                    selected = tab == i,
                    onClick = { tab = i },
                    text = { Text(title) }
                )
            }
        }
        when (tab) {
            0 -> DnsScreen(vm)
            1 -> TorScreen(vm)
            2 -> I2pScreen(vm)
            else -> RoutingScreen(vm)
        }
    }
}
